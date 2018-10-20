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
  nimcrypto/[bcmode, hash, keccak, rijndael],
  ../../eth_p2p, ../ecies

const
  flagsLen = 1 ## payload flags field length, bytes
  gcmIVLen = 12 ## Length of IV (seed) used for AES
  gcmTagLen = 16 ## Length of tag used to authenticate AES-GCM-encrypted message
  padMaxLen = 256 ## payload will be padded to multiples of this by default
  payloadLenLenBits = 0b11'u8 ## payload flags length-of-length mask
  signatureBits = 0b100'u8 ## payload flags signature mask
  whisperVersion* = 6

type
  Hash* = MDigest[256]
  SymKey* = array[256 div 8, byte] ## AES256 key
  Topic* = array[4, byte]
  Bloom* = array[64, byte]  ## XXX: nim-eth-bloom has really quirky API and fixed
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
    size*: uint64 ## RLP-encoded size of message
    pow*: float64 ## Calculated proof-of-work
    bloom*: Bloom ## Filter sent to direct peers for topic-based filtering

  Queue* = object
    ## Bounded message repository
    ##
    ## Whisper uses proof-of-work to judge the usefulness of a message staying
    ## in the "cloud" - messages with low proof-of-work will be removed to make
    ## room for those with higher pow, even if they haven't expired yet.
    ## Larger messages and those with high time-to-live will require more pow.
    items*: seq[Message] ## Sorted by proof-of-work

    capacity*: int ## Max messages to keep. \
    ## XXX: really big messages can cause excessive mem usage when using msg \
    ##      count

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
  result.size = env.toRlp().len().uint64 # XXX: calc len without creating RLP
  result.pow = calcPow(result.size, result.env.ttl, result.hash)

# Queues -----------------------------------------------------------------------

proc initQueue*(capacity: int): Queue =
  result.items = newSeqOfCap[Message](capacity)
  result.capacity = capacity

proc prune(self: var Queue) =
  ## Remove items that are past their expiry time
  let now = epochTime().uint64
  self.items.keepIf(proc(m: Message): bool = m.env.expiry > now)

proc add*(self: var Queue, msg: Message) =
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
        self.items.del(self.items.len() - 1)

  self.items.insert(msg, self.items.lowerBound(msg, cmpPow))

rlpxProtocol shh(version = whisperVersion):
  proc status(peer: Peer,
              protocolVersion: uint,
              powCoverted: uint,
              bloom: Bytes,
              isLightNode: bool) =
    discard

  proc messages(peer: Peer, envelopes: openarray[Envelope]) =
    discard

  proc powRequirement(peer: Peer, value: float64) =
    discard

  proc bloomFilterExchange(peer: Peer, bloom: Bytes) =
    discard

  nextID 126

  proc p2pRequest(peer: Peer, envelope: Envelope) =
    discard

  proc p2pMessage(peer: Peer, envelope: Envelope) =
    discard
