## Whisper
##
## Whisper is a gossip protocol that synchronizes a set of messages across nodes
## with attention given to sender and recipient anonymitiy. Messages are
## categorized by a topic and stay alive in the network based on a time-to-live
## measured in seconds. Spam prevention is based on proof-of-work, where large
## or long-lived messages must spend more work.

import
  algorithm,
  bitops,
  endians,
  eth_keys,
  eth_p2p/ecies,
  math,
  nimcrypto/hash,
  nimcrypto/keccak,
  nimcrypto/rijndael,
  options,
  rlp/types,
  rlp/writer,
  secp256k1,
  sequtils,
  strutils,
  tables,
  times

const
  PadLengthMask = 0b11000000'u8
  PadLengthPos  = 6
  SignedMask = 0b00100000'u8

type
  Hash = MDigest[256]
  SymKey = array[256 div 8, byte] ## AES256 key
  Topic = array[4, byte]
  Bloom = array[64, byte]  ## XXX: nim-eth-bloom has really quirky API and fixed
  ## bloom size.
  ## stint is massive overkill / poor fit - a bloom filter is an array of bits,
  ## not a number

  Payload = object
    ## Payload is what goes in the data field of the Envelope

    src: Option[PrivateKey] ## Optional key used for signing message
    dst: Option[PublicKey] ## Optional key used for asymmetric encryption
    symKey: Option[SymKey] ## Optional key used for symmetric encryption
    payload: seq[byte] ## Application data / message contents
    padding: seq[byte] ## Padding - if empty, will automatically pad up to
                       ## nearest 256-byte boundary

  Envelope = object
    ## What goes on the wire in the whisper protocol - a payload and some
    ## book-keeping
    ## Don't touch field order, there's lots of macro magic that depends on it
    expiry: uint64 ## Unix timestamp when message expires
    ttl: uint64 ## Time-to-live, seconds - message was created at (expiry - ttl)
    topic: Topic
    data: seq[byte] ## Payload, as given by user
    nonce: uint64 ## Nonce used for proof-of-work calculation

  Message = object
    ## An Envelope with a few cached properties

    env: Envelope
    hash: Hash ## Hash, as calculated for proof-of-work
    size: uint64 ## RLP-encoded size of message
    pow: float64 ## Calculated proof-of-work
    bloom: Bloom ## Filter sent to direct peers for topic-based filtering

  Queue = object
    ## Bounded message repository
    ##
    ## Whisper uses proof-of-work to judge the usefulness of a message staying
    ## in the "cloud" - messages with low proof-of-work will be removed to make
    ## room for those with higher pow, even if they haven't expired yet.
    ## Larger messages and those with high time-to-live will require more pow.
    items: seq[Message] ## Sorted by proof-of-work

    capacity: int ## Max messages to keep. \
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

proc topicBloom(topic: Topic): Bloom =
  ## Whisper uses 512-bit bloom filters meaning 9 bits of indexing - 3 9-bit
  ## indexes into the bloom are created using the first 3 bytes of the topic and
  ## complementing each byte with an extra bit from the last topic byte
  for i in 0..<3:
    var idx = uint16(topic[i])
    if (topic[3] and byte(1 shl i)) != 0: # fetch the 9'th bit from the last byte
      idx = idx + 256

    assert idx <= 511
    result[idx div 8] = result[idx div 8] or byte(1 shl (idx and 7'u16))

# Payloads ---------------------------------------------------------------------

# Several differences between geth and parity - this code is closer to geth
# simply because that makes it closer to EIP 627 - see also:
# https://github.com/paritytech/parity-ethereum/issues/9652

proc encode*(self: Payload): seq[byte] =
  ## Encode a payload according so as to make it suitable to put in an Envelope

  const
    FlagsLen = 1
    PadMaxLen = 256

  # length of the payload length field :)
  # XXX: deal with those extra large inputs we can't send
  let payloadLenLen =
    if self.payload.len >= 256*256: 3'u8
    elif self.payload.len >= 256: 2'u8
    else: 1'u8

  let signatureLen =
    if self.src.isSome(): RawSignatureSize
    else: 0

  # Upper boundary for buffer needs - we'll likely use a bit less
  let maxLen = FlagsLen + payloadLenLen.int + self.payload.len +
    self.padding.len + signatureLen + PadMaxLen

  var plain = newSeqOfCap[byte](maxLen)

  let signatureFlag =
    if self.src.isSome(): 0b100'u8
    else: 0'u8

  # byte 0: flags with payload length length and presence of signature
  plain.add payloadLenLen or signatureFlag

  # next, length of payload - little endian (who comes up with this stuff? why
  # can't the world just settle on one endian?)
  let payloadLen = self.payload.len.uint32.toLE

  # No, I have no love for nim closed ranges - such a mess to remember the extra
  # < or risk off-by-ones when working with lengths..
  plain.add payloadLen[0..<payloadLenLen]
  plain.add self.payload

  if self.padding.len > 0:
    plain.add self.padding
  else:
    let len = FlagsLen + payloadLenLen.int + self.payload.len + signatureLen
    let padLen = (len + 255) mod 256
    plain.add repeat(0'u8, padLen) # XXX: should be random

  if self.src.isSome(): # Private key present - signature requested
    let hash = keccak256.digest(plain)
    var sig: Signature
    # XXX: ugh, this raises sometimes, and returns a status code.. lovely.
    # XXX: handle some errors, or something
    discard signRawMessage(hash.data, self.src.get(), sig)
    plain.add sig.getRaw()

  if self.dst.isSome(): # Asymmetric key present - encryption requested
    result.setLen eciesEncryptedLength(plain.len)
    # XXX: handle those errors here also
    discard eciesEncrypt(plain, result, self.dst.get())
  elif self.symKey.isSome(): # Symmetric key present - encryption requested
    # https://github.com/cheatfate/nimcrypto/issues/11
    assert false, "no 256-bit GCM support in nimcrypto"
  else: # No encryption!
    result = plain

proc decode*(self: var Payload, data: openarray[byte]): bool =
  ## Decode data into payload, using keys found in self

  var plain: seq[byte]
  if self.src.isSome():
    plain.setLen(eciesDecryptedLength(data.len))
    if eciesDecrypt(data, plain, self.src.get()) != EciesStatus.Success:
      return false
  elif self.symKey.isSome():
    # https://github.com/cheatfate/nimcrypto/issues/11
    assert false, "no 256-bit GCM support in nimcrypto"
  else: # No encryption!
    plain = @data

  # XXX: bounds checking??
  let payloadLenLen = plain[0] and 0b11'u8
  let hasSignature = (plain[0] and 0b100'u8) != 0

  var payloadLen32: array[4, byte]

  for i in 0..<payloadLenLen.int: payloadLen32[i] = data[1 + i]

  let payloadLen = payloadLen32.fromLE32()

  self.payload.add data[2..<payloadLen + 2]

  # XXX check signatures and stuff..

# Envelopes --------------------------------------------------------------------

proc valid*(self: Envelope, now = epochTime()): bool =
  if self.expiry.float64 < now: return false # expired
  if self.ttl <= 0: return false # this would invalidate pow calculation

  let created = self.expiry - self.ttl
  if created.float64 > (now + 2.0): return false # created in the future

  return true

proc toShortRlp(self: Envelope): seq[byte] =
  ## RLP-encoded message without nonce is used during proof-of-work calculations
  writer.encodeList(self.expiry, self.ttl, self.topic, self.data)

proc toRlp(self: Envelope): seq[byte] =
  ## What gets sent out over the wire includes the nonce
  writer.encode(self)

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

proc calcPowHash(self: Envelope): Hash =
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

proc initMessage(env: Envelope): Message =
  result.env = env
  result.hash = env.calcPowHash()
  result.size = env.toRlp().len().uint64 # XXX: calc len without creating RLP
  result.pow = calcPow(result.size, result.env.ttl, result.hash)

# Queues -----------------------------------------------------------------------

proc initQueue(capacity: int): Queue =
  result.items = newSeqOfCap[Message](capacity)
  result.capacity = capacity

proc prune(self: var Queue) =
  ## Remove items that are past their expiry time
  let now = epochTime().uint64
  self.items.keepIf(proc(m: Message): bool = m.env.expiry > now)

proc add(self: var Queue, msg: Message) =
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

when false:
  rlpxProtocol shh, 6:
    proc status(p: Peer, values: openarray[KeyValuePair]) =
      discard

    proc status(p: Peer, values: openarray[KeyValuePair]) =
      discard

    proc messages(p: Peer, values: openarray[KeyValuePair]) =
      discard

    proc powRequirement(p: Peer, values: openarray[KeyValuePair]) =
      discard

    proc topicFilter(p: Peer, values: openarray[KeyValuePair]) =
      discard

if isMainModule:
  block:
    # Geth test: https://github.com/ethersphere/go-ethereum/blob/d3441ebb563439bac0837d70591f92e2c6080303/whisper/whisperv6/whisper_test.go#L834
    let top0 = [byte 0, 0, 255, 6]
    var x: Bloom
    x[0] = byte 1
    x[32] = byte 1
    x[^1] = byte 128
    doAssert @(top0.topicBloom) == @x

  # example from https://github.com/paritytech/parity-ethereum/blob/93e1040d07e385d1219d00af71c46c720b0a1acf/whisper/src/message.rs#L439
  let
    env0 = Envelope(expiry:100000, ttl: 30, topic: [byte 0, 0, 0, 0], data: repeat(byte 9, 256), nonce: 1010101)
    env1 = Envelope(expiry:100000, ttl: 30, topic: [byte 0, 0, 0, 0], data: repeat(byte 9, 256), nonce: 1010102)

  block:
    # XXX checked with parity, should check with geth too - found a potential bug
    #     in parity while playing with it:
    #     https://github.com/paritytech/parity-ethereum/issues/9625
    doAssert $calcPowHash(env0) == "A13B48480AEB3123CD2358516E2E8EE9FCB0F4CB37E68CD09FDF7F9A7E14767C"

  block:
    var queue = initQueue(1)

    let msg0 = initMessage(env0)
    let msg1 = initMessage(env1)

    queue.add(msg0)
    queue.add(msg1)

    doAssert queue.items.len() == 1

    doAssert queue.items[0].env.nonce ==
      (if msg0.pow > msg1.pow: msg0.env.nonce else: msg1.env.nonce)

  block:
    var queue = initQueue(2)

    queue.add(initMessage(env0))
    queue.add(initMessage(env1))

    doAssert queue.items.len() == 2

  block:
    doAssert writer.encode(env0) ==
      writer.encodeList(env0.expiry, env0.ttl, env0.topic, env0.data, env0.nonce)
