#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, unittest, times,
  nimcrypto/hash,
  eth_keys, rlp,
  eth_p2p/rlpx_protocols/shh_protocol as shh

suite "Whisper payload":
  test "should roundtrip without keys":
    let payload = Payload(payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.get().len == 251 # 256 -1 -1 -3

  test "should roundtrip with symmetric encryption":
    var symKey: SymKey
    let payload = Payload(symKey: some(symKey), payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get(), symKey = some(symKey))
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.get().len == 251 # 256 -1 -1 -3

  test "should roundtrip with signature":
    let privKey = eth_keys.newPrivateKey()

    let payload = Payload(src: some(privKey), payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      privKey.getPublicKey() == decoded.get().src.get()
      decoded.get().padding.get().len == 186 # 256 -1 -1 -3 -65

  test "should roundtrip with asymmetric encryption":
    let privKey = eth_keys.newPrivateKey()

    let payload = Payload(dst: some(privKey.getPublicKey()),
      payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get(), dst = some(privKey))
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.get().len == 251 # 256 -1 -1 -3

  test "should return specified bloom":
    # Geth test: https://github.com/ethersphere/go-ethereum/blob/d3441ebb563439bac0837d70591f92e2c6080303/whisper/whisperv6/whisper_test.go#L834
    let top0 = [byte 0, 0, 255, 6]
    var x: Bloom
    x[0] = byte 1
    x[32] = byte 1
    x[^1] = byte 128
    check @(top0.topicBloom) == @x

suite "Whisper payload padding":
  test "should do max padding":
    let payload = Payload(payload: repeat(byte 1, 254))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.isSome()
      decoded.get().padding.get().len == 256 # as dataLen == 256

  test "should do max padding with signature":
    let privKey = eth_keys.newPrivateKey()

    let payload = Payload(src: some(privKey), payload: repeat(byte 1, 189))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      privKey.getPublicKey() == decoded.get().src.get()
      decoded.get().padding.isSome()
      decoded.get().padding.get().len == 256 # as dataLen == 256

  test "should do min padding":
    let payload = Payload(payload: repeat(byte 1, 253))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.isSome()
      decoded.get().padding.get().len == 1 # as dataLen == 255

  test "should do min padding with signature":
    let privKey = eth_keys.newPrivateKey()

    let payload = Payload(src: some(privKey), payload: repeat(byte 1, 188))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      privKey.getPublicKey() == decoded.get().src.get()
      decoded.get().padding.isSome()
      decoded.get().padding.get().len == 1 # as dataLen == 255

  test "should roundtrip custom padding":
    let payload = Payload(payload: repeat(byte 1, 10),
                          padding: some(repeat(byte 2, 100)))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.isSome()
      payload.padding.get() == decoded.get().padding.get()

  test "should roundtrip custom 0 padding":
    let padding: seq[byte] = @[]
    let payload = Payload(payload: repeat(byte 1, 10),
                          padding: some(padding))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      decoded.get().padding.isNone()

  test "should roundtrip custom padding with signature":
    let privKey = eth_keys.newPrivateKey()
    let payload = Payload(src: some(privKey), payload: repeat(byte 1, 10),
                          padding: some(repeat(byte 2, 100)))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      privKey.getPublicKey() == decoded.get().src.get()
      decoded.get().padding.isSome()
      payload.padding.get() == decoded.get().padding.get()

  test "should roundtrip custom 0 padding with signature":
    let padding: seq[byte] = @[]
    let privKey = eth_keys.newPrivateKey()
    let payload = Payload(src: some(privKey), payload: repeat(byte 1, 10),
                          padding: some(padding))
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    check:
      decoded.isSome()
      payload.payload == decoded.get().payload
      privKey.getPublicKey() == decoded.get().src.get()
      decoded.get().padding.isNone()

# example from https://github.com/paritytech/parity-ethereum/blob/93e1040d07e385d1219d00af71c46c720b0a1acf/whisper/src/message.rs#L439
let
  env0 = Envelope(
    expiry:100000, ttl: 30, topic: [byte 0, 0, 0, 0],
    data: repeat(byte 9, 256), nonce: 1010101)
  env1 = Envelope(
    expiry:100000, ttl: 30, topic: [byte 0, 0, 0, 0],
    data: repeat(byte 9, 256), nonce: 1010102)

suite "Whisper envelope":
  test "should use correct fields for pow hash":
    # XXX checked with parity, should check with geth too - found a potential bug
    #     in parity while playing with it:
    #     https://github.com/paritytech/parity-ethereum/issues/9625
    check $calcPowHash(env0) ==
      "A13B48480AEB3123CD2358516E2E8EE9FCB0F4CB37E68CD09FDF7F9A7E14767C"

  test "should validate and allow envelope according to config":
    let ttl = 1'u32
    let topic = [byte 1, 2, 3, 4]
    let config = WhisperConfig(powRequirement: 0, bloom: topic.topicBloom(),
                               isLightNode: false, maxMsgSize: defaultMaxMsgSize)

    let env = Envelope(expiry:epochTime().uint32 + ttl, ttl: ttl, topic: topic,
                       data: repeat(byte 9, 256), nonce: 0)
    check env.valid()

    let msg = initMessage(env)
    check msg.allowed(config)

  test "should invalidate envelope due to ttl 0":
    let ttl = 0'u32
    let topic = [byte 1, 2, 3, 4]
    let config = WhisperConfig(powRequirement: 0, bloom: topic.topicBloom(),
                               isLightNode: false, maxMsgSize: defaultMaxMsgSize)

    let env = Envelope(expiry:epochTime().uint32 + ttl, ttl: ttl, topic: topic,
                       data: repeat(byte 9, 256), nonce: 0)
    check env.valid() == false

  test "should invalidate envelope due to expired":
    let ttl = 1'u32
    let topic = [byte 1, 2, 3, 4]
    let config = WhisperConfig(powRequirement: 0, bloom: topic.topicBloom(),
                               isLightNode: false, maxMsgSize: defaultMaxMsgSize)

    let env = Envelope(expiry:epochTime().uint32, ttl: ttl, topic: topic,
                       data: repeat(byte 9, 256), nonce: 0)
    check env.valid() == false

  test "should invalidate envelope due to in the future":
    let ttl = 1'u32
    let topic = [byte 1, 2, 3, 4]
    let config = WhisperConfig(powRequirement: 0, bloom: topic.topicBloom(),
                               isLightNode: false, maxMsgSize: defaultMaxMsgSize)

    # there is currently a 2 second tolerance, hence the + 3
    let env = Envelope(expiry:epochTime().uint32 + ttl + 3, ttl: ttl, topic: topic,
                       data: repeat(byte 9, 256), nonce: 0)
    check env.valid() == false

  test "should not allow envelope due to bloom filter":
    let topic = [byte 1, 2, 3, 4]
    let wrongTopic = [byte 9, 8, 7, 6]
    let config = WhisperConfig(powRequirement: 0, bloom: wrongTopic.topicBloom(),
                               isLightNode: false, maxMsgSize: defaultMaxMsgSize)

    let env = Envelope(expiry:100000 , ttl: 30, topic: topic,
                       data: repeat(byte 9, 256), nonce: 0)

    let msg = initMessage(env)
    check msg.allowed(config) == false


suite "Whisper queue":
  test "should throw out lower proof-of-work item when full":
    var queue = initQueue(1)

    let msg0 = initMessage(env0)
    let msg1 = initMessage(env1)

    discard queue.add(msg0)
    discard queue.add(msg1)

    check:
      queue.items.len() == 1
      queue.items[0].env.nonce ==
        (if msg0.pow > msg1.pow: msg0.env.nonce else: msg1.env.nonce)

  test "should not throw out messages as long as there is capacity":
    var queue = initQueue(2)

    check:
      queue.add(initMessage(env0)) == true
      queue.add(initMessage(env1)) == true

      queue.items.len() == 2

  test "check field order against expected rlp order":
    check rlp.encode(env0) ==
      rlp.encodeList(env0.expiry, env0.ttl, env0.topic, env0.data, env0.nonce)
