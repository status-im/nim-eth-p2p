## Whisper
##
## Whisper is a gossip protocol that synchronizes a set of messages across nodes
## with attention given to sender and recipient anonymitiy. Messages are
## categorized by a topic and stay alive in the network based on a time-to-live
## measured in seconds. Spam prevention is based on proof-of-work, where large
## or long-lived messages must spend more work.

import
  algorithm, bitops, endians, math, options, sequtils, strutils, tables, times,
  secp256k1, chronicles, asyncdispatch2, eth_common/eth_types, eth_keys, rlp,
  hashes, byteutils, nimcrypto/[bcmode, hash, keccak, rijndael, sysrand],
  ../../eth_p2p, ../ecies

const
  flagsLen = 1 ## payload flags field length, bytes
  gcmIVLen = 12 ## Length of IV (seed) used for AES
  gcmTagLen = 16 ## Length of tag used to authenticate AES-GCM-encrypted message
  padMaxLen = 256 ## payload will be padded to multiples of this by default
  payloadLenLenBits = 0b11'u8 ## payload flags length-of-length mask
  signatureBits = 0b100'u8 ## payload flags signature mask
  bloomSize = 512 div 8
  defaultQueueCapacity = 256
  defaultFilterQueueCapacity = 64
  whisperVersion* = 6
  defaultMinPow* = 0.001'f64
  defaultMaxMsgSize* = 1024'u32 * 1024'u32 # * 10 # should be no higher than max RLPx size

type
  Hash* = MDigest[256]
  SymKey* = array[256 div 8, byte] ## AES256 key
  Topic* = array[4, byte]
  Bloom* = array[bloomSize, byte]  ## XXX: nim-eth-bloom has really quirky API and fixed
  ## bloom size.
  ## stint is massive overkill / poor fit - a bloom filter is an array of bits,
  ## not a number

  Payload* = object
    ## Payload is what goes in the data field of the Envelope

    src*: Option[PrivateKey] ## Optional key used for signing message
    dst*: Option[PublicKey] ## Optional key used for asymmetric encryption
    symKey*: Option[SymKey] ## Optional key used for symmetric encryption
    payload*: Bytes ## Application data / message contents
    padding*: Option[Bytes] ## Padding - if unset, will automatically pad up to
                            ## nearest maxPadLen-byte boundary
  DecodedPayload* = object
    src*: Option[PublicKey] ## If the message was signed, this is the public key
                            ## of the source
    payload*: Bytes ## Application data / message contents
    padding*: Option[Bytes] ## Message padding

  Envelope* = object
    ## What goes on the wire in the whisper protocol - a payload and some
    ## book-keeping
    ## Don't touch field order, there's lots of macro magic that depends on it
    expiry*: uint32 ## Unix timestamp when message expires
    ttl*: uint32 ## Time-to-live, seconds - message was created at (expiry - ttl)
    topic*: Topic
    data*: Bytes ## Payload, as given by user
    nonce*: uint64 ## Nonce used for proof-of-work calculation

  Message* = object
    ## An Envelope with a few cached properties

    env*: Envelope
    hash*: Hash ## Hash, as calculated for proof-of-work
    size*: uint32 ## RLP-encoded size of message
    pow*: float64 ## Calculated proof-of-work
    bloom*: Bloom ## Filter sent to direct peers for topic-based filtering
    isP2P: bool

  ReceivedMessage* = object
    decoded*: DecodedPayload
    timestamp*: uint32
    ttl*: uint32
    topic*: Topic
    pow*: float64
    hash*: Hash

  Queue* = object
    ## Bounded message repository
    ##
    ## Whisper uses proof-of-work to judge the usefulness of a message staying
    ## in the "cloud" - messages with low proof-of-work will be removed to make
    ## room for those with higher pow, even if they haven't expired yet.
    ## Larger messages and those with high time-to-live will require more pow.
    items*: seq[Message] ## Sorted by proof-of-work
    itemHashes*: HashSet[Message] ## For easy duplication checking
    # XXX: itemHashes is added for easy message duplication checking and for
    # easy pruning of the peer received message sets. It does have an impact on
    # adding and pruning of items however.
    # Need to give it some more thought and check where most time is lost in
    # typical cases, perhaps we are better of with one hash table (lose PoW
    # sorting however), or perhaps there is a simpler solution...

    capacity*: int ## Max messages to keep. \
    ## XXX: really big messages can cause excessive mem usage when using msg \
    ##      count

  FilterMsgHandler* = proc(msg: ReceivedMessage) {.closure.}

  Filter* = object
    src: Option[PublicKey]
    privateKey: Option[PrivateKey]
    symKey: Option[SymKey]
    topics: seq[Topic]
    powReq: float64
    allowP2P: bool

    bloom: Bloom # cached bloom filter of all topics of filter
    handler: Option[FilterMsgHandler]
    queue: seq[ReceivedMessage]

  WhisperConfig* = object
    powRequirement*: float64
    bloom*: Bloom
    isLightNode*: bool
    maxMsgSize*: uint32

# Utilities --------------------------------------------------------------------

proc toBE(v: uint64): array[8, byte] =
  # return uint64 as bigendian array - for easy consumption with hash function
  var v = cast[array[8, byte]](v)
  bigEndian64(result.addr, v.addr)
proc toLE(v: uint32): array[4, byte] =
  # return uint32 as bigendian array - for easy consumption with hash function
  var v = cast[array[4, byte]](v)
  littleEndian32(result.addr, v.addr)

# XXX: get rid of pointer
proc fromLE32(v: array[4, byte]): uint32 =
  var v = v
  var ret: array[4, byte]
  littleEndian32(ret.addr, v.addr)
  result = cast[uint32](ret)

proc leadingZeroBits(hash: MDigest): int =
  ## Number of most significant zero bits before the first one
  for h in hash.data:
    static: assert sizeof(h) == 1
    if h == 0:
      result += 8
    else:
      result += countLeadingZeroBits(h)
      break

proc calcPow(size, ttl: uint64, hash: Hash): float64 =
  ## Whisper proof-of-work is defined as the best bit of a hash divided by
  ## encoded size and time-to-live, such that large and long-lived messages get
  ## penalized

  let bits = leadingZeroBits(hash) + 1
  return pow(2.0, bits.float64) / (size.float64 * ttl.float64)

proc topicBloom*(topic: Topic): Bloom =
  ## Whisper uses 512-bit bloom filters meaning 9 bits of indexing - 3 9-bit
  ## indexes into the bloom are created using the first 3 bytes of the topic and
  ## complementing each byte with an extra bit from the last topic byte
  for i in 0..<3:
    var idx = uint16(topic[i])
    if (topic[3] and byte(1 shl i)) != 0: # fetch the 9'th bit from the last byte
      idx = idx + 256

    assert idx <= 511
    result[idx div 8] = result[idx div 8] or byte(1 shl (idx and 7'u16))

proc generateRandomID(): string =
  var bytes: array[256 div 8, byte]
  while true: # XXX: error instead of looping?
    if randomBytes(bytes) == 256 div 8:
      result = toHex(bytes)
      break

proc `or`(a, b: Bloom): Bloom =
  for i in 0..<a.len:
    result[i] = a[i] or b[i]

proc bytesCopy(bloom: var Bloom, b: Bytes) =
  assert b.len == bloomSize
  # memcopy?
  for i in 0..<bloom.len:
    bloom[i] = b[i]

proc toBloom*(topics: openArray[Topic]): Bloom =
  #if topics.len == 0:
    # XXX: should we set the bloom here the all 1's ?
  for topic in topics:
    result = result or topicBloom(topic)

proc bloomFilterMatch(filter, sample: Bloom): bool =
  for i in 0..<filter.len:
    if (filter[i] or sample[i]) != filter[i]:
      return false
  return true

proc fullBloom*(): Bloom =
  for i in 0..<result.len:
    result[i] = 0xFF

proc emptyBloom*(): Bloom =
  for i in 0..<result.len:
    result[i] = 0x00

proc encryptAesGcm(plain: openarray[byte], key: SymKey,
    iv: array[gcmIVLen, byte]): Bytes =
  ## Encrypt using AES-GCM, making sure to append tag and iv, in that order
  var gcm: GCM[aes256]
  result = newSeqOfCap[byte](plain.len + gcmTagLen + iv.len)
  result.setLen plain.len
  gcm.init(key, iv, [])
  gcm.encrypt(plain, result)
  var tag: array[gcmTagLen, byte]
  gcm.getTag(tag)
  result.add tag
  result.add iv

proc decryptAesGcm(cipher: openarray[byte], key: SymKey): Option[Bytes] =
  ## Decrypt AES-GCM ciphertext and validate authenticity - assumes
  ## cipher-tag-iv format of the buffer
  if cipher.len < gcmTagLen + gcmIVLen:
    debug "cipher missing tag/iv", len = cipher.len
    return
  let plainLen = cipher.len - gcmTagLen - gcmIVLen
  var gcm: GCM[aes256]
  var res = newSeq[byte](plainLen)
  let iv = cipher[^gcmIVLen .. ^1]
  let tag = cipher[^(gcmIVLen + gcmTagLen) .. ^(gcmIVLen + 1)]
  gcm.init(key, iv, [])
  gcm.decrypt(cipher[0 ..< ^(gcmIVLen + gcmTagLen)], res)
  var tag2: array[gcmTagLen, byte]
  gcm.getTag(tag2)

  if tag != tag2:
    debug "cipher tag mismatch", len = cipher.len, tag, tag2
    return
  return some(res)

# Payloads ---------------------------------------------------------------------

# Several differences between geth and parity - this code is closer to geth
# simply because that makes it closer to EIP 627 - see also:
# https://github.com/paritytech/parity-ethereum/issues/9652

proc encode*(self: Payload): Option[Bytes] =
  ## Encode a payload according so as to make it suitable to put in an Envelope
  ## The format follows EIP 627 - https://eips.ethereum.org/EIPS/eip-627

  # XXX is this limit too high? We could limit it here but the protocol
  #     technically supports it..
  if self.payload.len >= 256*256*256:
    notice "Payload exceeds max length", len = self.payload.len
    return

  # length of the payload length field :)
  let payloadLenLen =
    if self.payload.len >= 256*256: 3'u8
    elif self.payload.len >= 256: 2'u8
    else: 1'u8

  let signatureLen =
    if self.src.isSome(): eth_keys.RawSignatureSize
    else: 0

  # useful data length
  let dataLen = flagsLen + payloadLenLen.int + self.payload.len + signatureLen

  let padLen =
    if self.padding.isSome(): self.padding.get().len
    # is there a reason why 256 bytes are padded when the dataLen is 256?
    else: padMaxLen - (dataLen mod padMaxLen)

  # buffer space that we need to allocate
  let totalLen = dataLen + padLen

  var plain = newSeqOfCap[byte](totalLen)

  let signatureFlag =
    if self.src.isSome(): signatureBits
    else: 0'u8

  # byte 0: flags with payload length length and presence of signature
  plain.add payloadLenLen or signatureFlag

  # next, length of payload - little endian (who comes up with this stuff? why
  # can't the world just settle on one endian?)
  let payloadLenLE = self.payload.len.uint32.toLE

  # No, I have no love for nim closed ranges - such a mess to remember the extra
  # < or risk off-by-ones when working with lengths..
  plain.add payloadLenLE[0..<payloadLenLen]
  plain.add self.payload

  if self.padding.isSome():
    plain.add self.padding.get()
  else:
    plain.add repeat(0'u8, padLen) # XXX: should be random

  if self.src.isSome(): # Private key present - signature requested
    let hash = keccak256.digest(plain)
    var sig: Signature
    let err = signRawMessage(hash.data, self.src.get(), sig)
    if err != EthKeysStatus.Success:
      notice "Signing message failed", err
      return

    plain.add sig.getRaw()

  if self.dst.isSome(): # Asymmetric key present - encryption requested
    var res = newSeq[byte](eciesEncryptedLength(plain.len))
    let err = eciesEncrypt(plain, res, self.dst.get())
    if err != EciesStatus.Success:
      notice "Encryption failed", err
      return
    return some(res)

  if self.symKey.isSome(): # Symmetric key present - encryption requested
    var iv: array[gcmIVLen, byte] # XXX: random!
    return some(encryptAesGcm(plain, self.symKey.get(), iv))

  # No encryption!
  return some(plain)

proc decode*(data: openarray[byte], dst = none[PrivateKey](),
    symKey = none[SymKey]()): Option[DecodedPayload] =
  ## Decode data into payload, potentially trying to decrypt if keys are
  ## provided

  # Careful throughout - data coming from unknown source - malformatted data
  # expected

  var res: DecodedPayload

  var plain: Bytes
  if dst.isSome():
    # XXX: eciesDecryptedLength is pretty fragile, API-wise.. is this really the
    #      way to check for errors / sufficient length?
    let plainLen = eciesDecryptedLength(data.len)
    if plainLen < 0:
      debug "Not enough data to decrypt", len = data.len
      return

    plain.setLen(eciesDecryptedLength(data.len))
    if eciesDecrypt(data, plain, dst.get()) != EciesStatus.Success:
      debug "Couldn't decrypt using asymmetric key", len = data.len
      return
  elif symKey.isSome():
    let tmp = decryptAesGcm(data, symKey.get())
    if tmp.isNone():
      debug "Couldn't decrypt using symmetric key", len = data.len
      return

    plain = tmp.get()
  else: # No encryption!
    plain = @data

  if plain.len < 2: # Minimum 1 byte flags, 1 byte payload len
    debug "Missing flags or payload length", len = plain.len
    return

  var pos = 0

  let payloadLenLen = int(plain[pos] and 0b11'u8)
  let hasSignature = (plain[pos] and 0b100'u8) != 0

  pos += 1

  if plain.len < pos + payloadLenLen:
    debug "Missing payload length", len = plain.len, pos, payloadLenLen
    return

  var payloadLenLE: array[4, byte]

  for i in 0..<payloadLenLen: payloadLenLE[i] = plain[pos + i]
  pos += payloadLenLen

  let payloadLen = int(payloadLenLE.fromLE32())
  if plain.len < pos + payloadLen:
    debug "Missing payload", len = plain.len, pos, payloadLen
    return

  res.payload = plain[pos ..< pos + payloadLen]

  pos += payloadLen

  if hasSignature:
    if plain.len < (eth_keys.RawSignatureSize + pos):
      debug "Missing expected signature", len = plain.len
      return

    let sig = plain[^eth_keys.RawSignatureSize .. ^1]
    let hash = keccak256.digest(plain[0 ..< ^eth_keys.RawSignatureSize])
    var key: PublicKey
    let err = recoverSignatureKey(sig, hash.data, key)
    if err != EthKeysStatus.Success:
      debug "Failed to recover signature key", err
      return
    res.src = some(key)

  if hasSignature:
    if plain.len > pos + eth_keys.RawSignatureSize:
      res.padding = some(plain[pos .. ^(eth_keys.RawSignatureSize+1)])
  else:
    if plain.len > pos:
      res.padding = some(plain[pos .. ^1])

  return some(res)

# Envelopes --------------------------------------------------------------------

proc valid*(self: Envelope, now = epochTime()): bool =
  if self.expiry.float64 < now: return false # expired
  if self.ttl <= 0: return false # this would invalidate pow calculation

  let created = self.expiry - self.ttl
  if created.float64 > (now + 2.0): return false # created in the future

  return true

proc toShortRlp(self: Envelope): Bytes =
  ## RLP-encoded message without nonce is used during proof-of-work calculations
  rlp.encodeList(self.expiry, self.ttl, self.topic, self.data)

proc toRlp(self: Envelope): Bytes =
  ## What gets sent out over the wire includes the nonce
  rlp.encode(self)

# NOTE: minePow and calcPowHash are different from go-ethereum implementation.
# Is correct however with EIP-627, but perhaps this is not up to date.
# Follow-up here: https://github.com/ethereum/go-ethereum/issues/18070

proc minePow*(self: Envelope, seconds: float): uint64 =
  ## For the given envelope, spend millis milliseconds to find the
  ## best proof-of-work and return the nonce
  let bytes = self.toShortRlp()

  var ctx: keccak256
  ctx.init()
  ctx.update(bytes)

  var bestPow: float64 = 0.0

  let mineEnd = epochTime() + seconds

  var i: uint64
  while epochTime() < mineEnd or bestPow == 0: # At least one round
    var tmp = ctx # copy hash calculated so far - we'll reuse that for each iter
    tmp.update(i.toBE())
    i.inc
    # XXX:a random nonce here would not leak number of iters
    let pow = calcPow(1, 1, tmp.finish())
    if pow > bestPow: # XXX: could also compare hashes as numbers instead
      bestPow = pow
      result = i.uint64

proc calcPowHash*(self: Envelope): Hash =
  ## Calculate the message hash, as done during mining - this can be used to
  ## verify proof-of-work

  let bytes = self.toShortRlp()

  var ctx: keccak256
  ctx.init()
  ctx.update(bytes)
  ctx.update(self.nonce.toBE())
  return ctx.finish()

# Messages ---------------------------------------------------------------------

proc cmpPow(a, b: Message): int =
  ## Biggest pow first, lowest at the end (for easy popping)
  if a.pow > b.pow: 1
  elif a.pow == b.pow: 0
  else: -1

proc initMessage*(env: Envelope): Message =
  result.env = env
  result.hash = env.calcPowHash()
  result.size = env.toRlp().len().uint32 # XXX: calc len without creating RLP
  result.pow = calcPow(result.size, result.env.ttl, result.hash)
  result.bloom = topicBloom(env.topic)

proc hash*(msg: Message): hashes.Hash = hash(msg.hash.data)

proc allowed*(msg: Message, config: WhisperConfig): bool =
  # Check max msg size, already happens in RLPx but there is a specific shh
  # max msg size which should always be < RLPx max msg size
  if msg.size > config.maxMsgSize:
    warn "Message size too large", size = msg.size
    return false

  if msg.pow < config.powRequirement:
    warn "Message PoW too low", pow = msg.pow, minPow = config.powRequirement
    return false

  if not bloomFilterMatch(config.bloom, msg.bloom):
    warn "Message does not match node bloom filter"
    return false

  return true

# Queues -----------------------------------------------------------------------

proc initQueue*(capacity: int): Queue =
  result.items = newSeqOfCap[Message](capacity)
  result.capacity = capacity
  result.itemHashes.init()

proc prune(self: var Queue) =
  ## Remove items that are past their expiry time
  let now = epochTime().uint32

  # keepIf code + pruning of hashset
  var pos = 0
  for i in 0 ..< len(self.items):
    if self.items[i].env.expiry > now:
      if pos != i:
        shallowCopy(self.items[pos], self.items[i])
      inc(pos)
    else: self.itemHashes.excl(self.items[i])
  setLen(self.items, pos)

proc add*(self: var Queue, msg: Message): bool =
  ## Add a message to the queue.
  ## If we're at capacity, we will be removing, in order:
  ## * expired messages
  ## * lowest proof-of-work message - this may be `msg` itself!

  if self.items.len >= self.capacity:
    self.prune() # Only prune if needed

    if self.items.len >= self.capacity:
      # Still no room - go by proof-of-work quantity
      let last = self.items[^1]

      if last.pow > msg.pow or
        (last.pow == msg.pow and last.env.expiry > msg.env.expiry):
        # The new message has less pow or will expire earlier - drop it
        return false

      self.items.del(self.items.len() - 1)
      self.itemHashes.excl(last)

  # check for duplicate
  # NOTE: Could also track if duplicates come from the same peer and disconnect
  # from that peer. Is this tracking overhead worth it though?
  if self.itemHashes.containsOrIncl(msg):
    return false
  else:
    self.items.insert(msg, self.items.lowerBound(msg, cmpPow))
    return true

# Filters ----------------------------------------------------------------------
proc newFilter*(src = none[PublicKey](), privateKey = none[PrivateKey](),
                symKey = none[SymKey](), topics: seq[Topic] = @[],
                powReq = 0.0, allowP2P = false): Filter =
  Filter(src: src, privateKey: privateKey, symKey: symKey, topics: topics,
         powReq: powReq, allowP2P: allowP2P, bloom: toBloom(topics))

proc notify(filters: var Table[string, Filter], msg: Message) =
 var decoded: Option[DecodedPayload]
 var keyHash: Hash

 for filter in filters.mvalues:
   if not filter.allowP2P and msg.isP2P:
     continue

   # if message is direct p2p PoW doesn't matter
   if msg.pow < filter.powReq and not msg.isP2P:
     continue

   if filter.topics.len > 0:
     if msg.env.topic notin filter.topics:
       continue

   # Decode, if already decoded previously check if hash of key matches
   if decoded.isNone():
     decoded = decode(msg.env.data, dst = filter.privateKey,
                      symKey = filter.symKey)
     if filter.privateKey.isSome():
       keyHash = keccak256.digest(filter.privateKey.get().data)
     elif filter.symKey.isSome():
       keyHash = keccak256.digest(filter.symKey.get())
     # else:
       # NOTE: should we error on messages without encryption?
     if decoded.isNone():
       continue
   else:
     if filter.privateKey.isSome():
       if keyHash != keccak256.digest(filter.privateKey.get().data):
         continue
     elif filter.symKey.isSome():
       if keyHash != keccak256.digest(filter.symKey.get()):
         continue
     # else:
       # NOTE: should we error on messages without encryption?

   # When decoding is done we can check the src (signature)
   if filter.src.isSome():
     let src: Option[PublicKey] = decoded.get().src
     if not src.isSome():
       continue
     elif src.get() != filter.src.get():
       continue

   let receivedMsg = ReceivedMessage(decoded: decoded.get(),
                                     timestamp: msg.env.expiry - msg.env.ttl,
                                     ttl: msg.env.ttl,
                                     topic: msg.env.topic,
                                     pow: msg.pow,
                                     hash: msg.hash)
   # Either run callback or add to queue
   if filter.handler.isSome():
     filter.handler.get()(receivedMsg)
   else:
     filter.queue.insert(receivedMsg)

type
  PeerState = ref object
    initialized*: bool # when successfully completed the handshake
    powRequirement*: float64
    bloom*: Bloom
    isLightNode*: bool
    trusted*: bool
    received: HashSet[Message]
    running*: bool

  WhisperState = ref object
    queue*: Queue
    filters*: Table[string, Filter]
    config*: WhisperConfig

proc run(peer: Peer) {.async.}
proc run(node: EthereumNode, network: WhisperState) {.async.}

proc initProtocolState*(network: var WhisperState, node: EthereumNode) =
  network.queue = initQueue(defaultQueueCapacity)
  network.filters = initTable[string, Filter]()
  network.config.bloom = fullBloom()
  network.config.powRequirement = defaultMinPow
  network.config.isLightNode = false
  network.config.maxMsgSize = defaultMaxMsgSize
  asyncCheck node.run(network)

rlpxProtocol shh(version = whisperVersion,
                 peerState = PeerState,
                 networkState = WhisperState):

  onPeerConnected do (peer: Peer):
    debug "onPeerConnected Whisper"
    let
      shhNetwork = peer.networkState
      shhPeer = peer.state

    asyncCheck peer.status(whisperVersion,
                           cast[uint](shhNetwork.config.powRequirement),
                           @(shhNetwork.config.bloom),
                           shhNetwork.config.isLightNode)

    var f = peer.nextMsg(shh.status)
    # When the peer does not respond with status within 500 ms we disconnect
    await f or sleepAsync(500)
    if not f.finished:
      raise newException(UselessPeerError, "No status message received")

    let m = f.read()

    if m.protocolVersion == whisperVersion:
      debug "Suitable Whisper peer", peer, whisperVersion
    else:
      raise newException(UselessPeerError, "Incompatible Whisper version")

    shhPeer.powRequirement = cast[float64](m.powConverted)

    if m.bloom.len > 0:
      if m.bloom.len != bloomSize:
        raise newException(UselessPeerError, "Bloomfilter size mismatch")
      else:
        shhPeer.bloom.bytesCopy(m.bloom)
    else:
      # If no bloom filter is send we allow all
      shhPeer.bloom = fullBloom()

    shhPeer.isLightNode = m.isLightNode
    if shhPeer.isLightNode and shhNetwork.config.isLightNode:
      # No sense in connecting two light nodes so we disconnect
      raise newException(UselessPeerError, "Two light nodes connected")

    shhPeer.received.init()
    shhPeer.trusted = false
    shhPeer.initialized = true

    asyncCheck peer.run()
    debug "Whisper peer initialized"

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason) {.gcsafe.}:
     peer.state.running = false

  proc status(peer: Peer,
              protocolVersion: uint,
              powConverted: uint,
              bloom: Bytes,
              isLightNode: bool) =
    discard

  proc messages(peer: Peer, envelopes: openarray[Envelope]) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding messages"
      return

    for envelope in envelopes:
      # check if expired or in future, or ttl not 0
      if not envelope.valid():
        warn "Expired or future timed envelope"
        # disconnect from peers sending bad envelopes
        # await peer.disconnect(SubprotocolReason)
        continue

      let msg = initMessage(envelope)
      if not msg.allowed(peer.networkState.config):
        # disconnect from peers sending bad envelopes
        # await peer.disconnect(SubprotocolReason)
        continue

      # This peer send it thus should not receive it again
      peer.state(shh).received.incl(msg)

      if peer.networkState.queue.add(msg):
        # notify filters of this message
        peer.networkState.filters.notify(msg)

  proc powRequirement(peer: Peer, value: uint) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding powRequirement"
      return

    peer.state.powRequirement = cast[float64](value)

  proc bloomFilterExchange(peer: Peer, bloom: Bytes) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding bloomFilterExchange"
      return

    peer.state.bloom.bytesCopy(bloom)

  nextID 126

  proc p2pRequest(peer: Peer, envelope: Envelope) =
    # TODO: here we would have to allow to insert some specific implementation
    # such as e.g. Whisper Mail Server
    discard

  proc p2pMessage(peer: Peer, envelope: Envelope) =
    if peer.state.trusted:
      # when trusted we can bypass any checks on envelope
      let msg = Message(env: envelope, isP2P: true)
      peer.networkState.filters.notify(msg)

# 'Runner' calls ---------------------------------------------------------------

proc processQueue(peer: Peer) =
  var envelopes: seq[Envelope] = @[]
  for message in peer.networkState(shh).queue.items:
    if peer.state(shh).received.contains(message):
      # debug "message was already send to peer"
      continue

    if message.pow < peer.state(shh).powRequirement:
      debug "Message PoW too low for peer"
      continue

    if not bloomFilterMatch(peer.state(shh).bloom, message.bloom):
      debug "Message does not match peer bloom filter"
      continue

    debug "Adding envelope"
    envelopes.add(message.env)
    peer.state(shh).received.incl(message)

  debug "Sending envelopes", amount=envelopes.len
  # await peer.messages(envelopes)
  asyncCheck peer.messages(envelopes)

proc run(peer: Peer) {.async.} =
  peer.state(shh).running = true
  while peer.state(shh).running:
    if not peer.networkState(shh).config.isLightNode:
      peer.processQueue()
    await sleepAsync(300)

proc pruneReceived(node: EthereumNode) =
  if node.peerPool != nil: # XXX: a bit dirty to need to check for this here ...
    for peer in node.peers(shh):
      if not peer.state(shh).initialized:
        continue

      # NOTE: Perhaps alter the queue prune call to keep track of a HashSet
      # of pruned messages (as these should be smaller), and diff this with
      # the received sets.
      peer.state(shh).received = intersection(peer.state(shh).received,
                                              node.protocolState(shh).queue.itemHashes)

proc run(node: EthereumNode, network: WhisperState) {.async.} =
  while true:
    # prune message queue every second
    # TTL unit is in seconds, so this should be sufficient?
    network.queue.prune()
    # pruning the received sets is not necessary for correct workings
    # but simply from keeping the sets growing indefinitely
    node.pruneReceived()
    await sleepAsync(1000)

# Public EthereumNode calls ----------------------------------------------------

proc sendP2PMessage*(node: EthereumNode, peerId: NodeId, env: Envelope): bool =
  for peer in node.peers(shh):
    if peer.remote.id == peerId:
      asyncCheck peer.p2pMessage(env)
      return true

proc sendMessage*(node: EthereumNode, env: var Envelope): bool =
  if not env.valid(): # actually just ttl !=0 is sufficient
    return false

  # We have to do the same checks here as in the messages proc not to leak
  # any information that the message originates from this node.
  let msg = initMessage(env)
  if not msg.allowed(node.protocolState(shh).config):
    return false

  debug "Adding message to queue"
  if node.protocolState(shh).queue.add(msg):
    # Also notify our own filters of the message we are sending,
    # e.g. msg from local Dapp to Dapp
    node.protocolState(shh).filters.notify(msg)

  return true

proc postMessage*(node: EthereumNode, pubKey = none[PublicKey](),
                  symKey = none[SymKey](), src = none[PrivateKey](),
                  ttl: uint32, topic: Topic, payload: Bytes,
                  padding = none[Bytes](), powTime = 1'f,
                  targetPeer = none[NodeId]()): bool =
  # NOTE: Allow a post without a key? Encryption is mandatory in v6?
  let payload = encode(Payload(payload: payload, src: src, dst: pubKey,
                               symKey: symKey, padding: padding))
  if payload.isSome():
    var env = Envelope(expiry:epochTime().uint32 + ttl + powTime.uint32,
                       ttl: ttl, topic: topic, data: payload.get(), nonce: 0)

    # Allow lightnode to post only direct p2p messages
    if targetPeer.isSome():
      return node.sendP2PMessage(targetPeer.get(), env)
    elif not node.protocolState(shh).config.isLightNode:
      # XXX: make this non blocking or not?
      # In its current blocking state, it could be noticed by a peer that no
      # messages are send for a while, and thus that mining PoW is done, and that
      # next messages contains a message originated from this peer
      env.nonce = env.minePow(powTime)
      return node.sendMessage(env)
    else:
      error "Light node not allowed to post messages"
      return false
  else:
    error "Encoding of payload failed"
    return false

proc subscribeFilter*(node: EthereumNode, filter: Filter,
                      handler = none[FilterMsgHandler]()): string =
  # NOTE: Should we allow a filter without a key? Encryption is mandatory in v6?
  # Check if asymmetric _and_ symmetric key? Now asymmetric just has precedence.
  let id = generateRandomID()
  var filter = filter
  if handler.isSome():
    filter.handler = handler
  else:
    filter.queue = newSeqOfCap[ReceivedMessage](defaultFilterQueueCapacity)
  node.protocolState(shh).filters.add(id, filter)
  debug "Filter added", filter = id
  return id

proc unsubscribeFilter*(node: EthereumNode, filterId: string): bool =
  var filter: Filter
  return node.protocolState(shh).filters.take(filterId, filter)

proc getFilterMessages*(node: EthereumNode, filterId: string): seq[ReceivedMessage] =
  result = @[]
  if node.protocolState(shh).filters.contains(filterId):
    if node.protocolState(shh).filters[filterId].handler.isNone():
      result = node.protocolState(shh).filters[filterId].queue
      node.protocolState(shh).filters[filterId].queue =
        newSeqOfCap[ReceivedMessage](defaultFilterQueueCapacity)

proc setPowRequirement*(node: EthereumNode, powReq: float64) {.async.} =
  # NOTE: do we need a tolerance of old PoW for some time?
  node.protocolState(shh).config.powRequirement = powReq
  for peer in node.peers(shh):
    # asyncCheck peer.powRequirement(cast[uint](powReq))
    await peer.powRequirement(cast[uint](powReq))

proc setBloomFilter*(node: EthereumNode, bloom: Bloom) {.async.} =
  # NOTE: do we need a tolerance of old bloom filter for some time?
  node.protocolState(shh).config.bloom = bloom
  for peer in node.peers(shh):
    # asyncCheck peer.bloomFilterExchange(@bloom)
    await peer.bloomFilterExchange(@bloom)

proc filtersToBloom*(node: EthereumNode): Bloom =
  for filter in node.protocolState(shh).filters.values:
    if filter.topics.len > 0:
      result = result or filter.bloom

proc setMaxMessageSize*(node: EthereumNode, size: uint32): bool =
  if size > defaultMaxMsgSize:
    error "size > maxMsgSize"
    return false
  node.protocolState(shh).config.maxMsgSize = size
  return true

proc setPeerTrusted*(node: EthereumNode, peerId: NodeId): bool =
  for peer in node.peers(shh):
    if peer.remote.id == peerId:
      peer.state(shh).trusted = true
      return true

# XXX: should probably only be allowed before connection is made,
# as there exists no message to communicate to peers that it is a light node
# How to arrange that?
proc setLightNode*(node: EthereumNode, isLightNode: bool) =
  node.protocolState(shh).config.isLightNode = isLightNode
