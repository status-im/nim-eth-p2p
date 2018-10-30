#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, unittest,
  nimcrypto/hash,
  eth_keys, rlp,
  eth_p2p/rlpx_protocols/shh_protocol as shh

suite "Whisper payload":
  test "should roundtrip without keys":
    let payload = Payload(payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    doAssert decoded.isSome()
    doAssert payload.payload == decoded.get().payload

  test "should roundtrip with symmetric encryption":
    var symKey: SymKey
    let payload = Payload(symKey: some(symKey), payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get(), symKey = some(symKey))
    doAssert decoded.isSome()
    doAssert payload.payload == decoded.get().payload

  test "should roundtrip with signature":
    let privKey = eth_keys.newPrivateKey()

    let payload = Payload(src: some(privKey), payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get())
    doAssert decoded.isSome()
    doAssert payload.payload == decoded.get().payload
    doAssert privKey.getPublicKey() == decoded.get().src.get()

  test "should roundtrip with asymmetric encryption":
    let privKey = eth_keys.newPrivateKey()

    let payload = Payload(dst: some(privKey.getPublicKey()),
      payload: @[byte 0, 1, 2])
    let encoded = shh.encode(payload)

    let decoded = shh.decode(encoded.get(), dst = some(privKey))
    doAssert decoded.isSome()
    doAssert payload.payload == decoded.get().payload

  test "should roundtrip with asymmetric encryption":
    # Geth test: https://github.com/ethersphere/go-ethereum/blob/d3441ebb563439bac0837d70591f92e2c6080303/whisper/whisperv6/whisper_test.go#L834
    let top0 = [byte 0, 0, 255, 6]
    var x: Bloom
    x[0] = byte 1
    x[32] = byte 1
    x[^1] = byte 128
    doAssert @(top0.topicBloom) == @x

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
    doAssert $calcPowHash(env0) ==
      "A13B48480AEB3123CD2358516E2E8EE9FCB0F4CB37E68CD09FDF7F9A7E14767C"

suite "Whisper queue":
  test "should throw out lower proof-of-work item when full":
    var queue = initQueue(1)

    let msg0 = initMessage(env0)
    let msg1 = initMessage(env1)

    queue.add(msg0)
    queue.add(msg1)

    doAssert queue.items.len() == 1

    doAssert queue.items[0].env.nonce ==
      (if msg0.pow > msg1.pow: msg0.env.nonce else: msg1.env.nonce)

  test "should not throw out messages as long as there is capacity":
    var queue = initQueue(2)

    queue.add(initMessage(env0))
    queue.add(initMessage(env1))

    doAssert queue.items.len() == 2

  test "check field order against expected rlp order":
    doAssert rlp.encode(env0) ==
      rlp.encodeList(env0.expiry, env0.ttl, env0.topic, env0.data, env0.nonce)
