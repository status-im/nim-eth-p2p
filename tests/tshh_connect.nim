#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, unittest, tables, asyncdispatch2, rlp, eth_keys,
  eth_p2p, eth_p2p/rlpx_protocols/[shh_protocol], eth_p2p/[discovery, enode]

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

proc startDiscoveryNode(privKey: PrivateKey, address: Address,
                        bootnodes: seq[ENode]): Future[DiscoveryProtocol] {.async.} =
  result = newDiscoveryProtocol(privKey, address, bootnodes)
  result.open()
  await result.bootstrap()

proc setupBootNode(): Future[ENode] {.async.} =
  let
    bootNodeKey = newPrivateKey()
    bootNodeAddr = localAddress(30301)
    bootNode = await startDiscoveryNode(bootNodeKey, bootNodeAddr, @[])
  result = initENode(bootNodeKey.getPublicKey, bootNodeAddr)

template asyncTest(name, body: untyped) =
  test name:
    proc scenario {.async.} = body
    waitFor scenario()

const useCompression = defined(useSnappy)
let
  keys1 = newKeyPair()
  keys2 = newKeyPair()
var node1 = newEthereumNode(keys1, localAddress(30303), 1, nil,
                            addAllCapabilities = false,
                            useCompression = useCompression)
node1.addCapability Whisper

var node2 = newEthereumNode(keys2, localAddress(30304), 1, nil,
                            addAllCapabilities = false,
                            useCompression = useCompression)
node2.addCapability Whisper

template waitForEmptyQueues() =
  while node1.protocolState(Whisper).queue.items.len != 0 or
        node2.protocolState(Whisper).queue.items.len != 0: poll()

when not defined(directConnect):
  let bootENode = waitFor setupBootNode()

  # node2 listening and node1 not, to avoid many incoming vs outgoing
  var node1Connected = node1.connectToNetwork(@[bootENode], false, true)
  var node2Connected = node2.connectToNetwork(@[bootENode], true, true)
  waitFor node1Connected
  waitFor node2Connected

  asyncTest "Two peers connected":
    check:
      node1.peerPool.connectedNodes.len() == 1
      node2.peerPool.connectedNodes.len() == 1
else: # XXX: tricky without peerPool
  node2.startListening()
  discard waitFor node1.rlpxConnect(newNode(initENode(node2.keys.pubKey,
                                                      node2.address)))

asyncTest "Filters with encryption and signing":
  let encryptKeyPair = newKeyPair()
  let signKeyPair = newKeyPair()
  var symKey: SymKey
  let topic = [byte 0x12, 0, 0, 0]
  var filters: seq[string] = @[]
  var payloads = [repeat(byte 1, 10), repeat(byte 2, 10),
                  repeat(byte 3, 10), repeat(byte 4, 10)]
  var futures = [newFuture[int](), newFuture[int](),
                 newFuture[int](), newFuture[int]()]

  proc handler1(msg: ReceivedMessage) =
    var count {.global.}: int
    check msg.decoded.payload == payloads[0] or msg.decoded.payload == payloads[1]
    count += 1
    if count == 2: futures[0].complete(1)
  proc handler2(msg: ReceivedMessage) =
    check msg.decoded.payload == payloads[1]
    futures[1].complete(1)
  proc handler3(msg: ReceivedMessage) =
    var count {.global.}: int
    check msg.decoded.payload == payloads[2] or msg.decoded.payload == payloads[3]
    count += 1
    if count == 2: futures[2].complete(1)
  proc handler4(msg: ReceivedMessage) =
    check msg.decoded.payload == payloads[3]
    futures[3].complete(1)

  # Filters
  # filter for encrypted asym
  filters.add(node1.subscribeFilter(newFilter(privateKey = some(encryptKeyPair.seckey),
                                              topics = @[topic]), some(handler1)))
  # filter for encrypted asym + signed
  filters.add(node1.subscribeFilter(newFilter(some(signKeyPair.pubkey),
                                              privateKey = some(encryptKeyPair.seckey),
                                              topics = @[topic]), some(handler2)))
  # filter for encrypted sym
  filters.add(node1.subscribeFilter(newFilter(symKey = some(symKey),
                                              topics = @[topic]), some(handler3)))
  # filter for encrypted sym + signed
  filters.add(node1.subscribeFilter(newFilter(some(signKeyPair.pubkey),
                                              symKey = some(symKey),
                                              topics = @[topic]), some(handler4)))
  # Messages
  # encrypted asym
  check true == node2.postMessage(some(encryptKeyPair.pubkey), ttl = 5,
                                  topic = topic, payload = payloads[0])
  # encrypted asym + signed
  check true == node2.postMessage(some(encryptKeyPair.pubkey),
                                  src = some(signKeyPair.seckey), ttl = 4,
                                  topic = topic, payload = payloads[1])
  # encrypted sym
  check true == node2.postMessage(symKey = some(symKey), ttl = 3, topic = topic,
                                  payload = payloads[2])
  # encrypted sym + signed
  check true == node2.postMessage(symKey = some(symKey),
                                  src = some(signKeyPair.seckey), ttl = 2,
                                  topic = topic, payload = payloads[3])

  check node2.protocolState(Whisper).queue.items.len == 4

  var f = all(futures)
  await f or sleepAsync(300)
  check:
    f.finished == true
    node1.protocolState(Whisper).queue.items.len == 4

  for filter in filters:
    check node1.unsubscribeFilter(filter) == true

  waitForEmptyQueues()

asyncTest "Filters with topics":
  let topic1 = [byte 0x12, 0, 0, 0]
  let topic2 = [byte 0x34, 0, 0, 0]
  var payloads = [repeat(byte 0, 10), repeat(byte 1, 10)]
  var futures = [newFuture[int](), newFuture[int]()]
  proc handler1(msg: ReceivedMessage) =
    check msg.decoded.payload == payloads[0]
    futures[0].complete(1)
  proc handler2(msg: ReceivedMessage) =
    check msg.decoded.payload == payloads[1]
    futures[1].complete(1)

  var filter1 = node1.subscribeFilter(newFilter(topics = @[topic1]), some(handler1))
  var filter2 = node1.subscribeFilter(newFilter(topics = @[topic2]), some(handler2))

  check:
    true == node2.postMessage(ttl = 3, topic = topic1, payload = payloads[0])
    true == node2.postMessage(ttl = 2, topic = topic2, payload = payloads[1])

  var f = all(futures)
  await f or sleepAsync(300)
  check:
    f.finished == true
    node1.protocolState(Whisper).queue.items.len == 2

    node1.unsubscribeFilter(filter1) == true
    node1.unsubscribeFilter(filter2) == true

  waitForEmptyQueues()

asyncTest "Filters with PoW":
  let topic = [byte 0x12, 0, 0, 0]
  var payload = repeat(byte 0, 10)
  var futures = [newFuture[int](), newFuture[int]()]
  proc handler1(msg: ReceivedMessage) =
    check msg.decoded.payload == payload
    futures[0].complete(1)
  proc handler2(msg: ReceivedMessage) =
    check msg.decoded.payload == payload
    futures[1].complete(1)

  var filter1 = node1.subscribeFilter(newFilter(topics = @[topic], powReq = 0),
                                      some(handler1))
  var filter2 = node1.subscribeFilter(newFilter(topics = @[topic], powReq = 10),
                                      some(handler2))

  check:
    true == node2.postMessage(ttl = 2, topic = topic, payload = payload)

  await futures[0] or sleepAsync(300)
  await futures[1] or sleepAsync(300)
  check:
    futures[0].finished == true
    futures[1].finished == false
    node1.protocolState(Whisper).queue.items.len == 1

    node1.unsubscribeFilter(filter1) == true
    node1.unsubscribeFilter(filter2) == true

  waitForEmptyQueues()

asyncTest "Filters with queues":
  let topic = [byte 0, 0, 0, 0]
  let payload = repeat(byte 0, 10)

  var filter = node1.subscribeFilter(newFilter(topics = @[topic]))
  for i in countdown(10, 1):
    check true == node2.postMessage(ttl = i.uint32, topic = topic,
                                    payload = payload)

  await sleepAsync(300)
  check:
    node1.getFilterMessages(filter).len() == 10
    node1.getFilterMessages(filter).len() == 0
    node1.unsubscribeFilter(filter) == true

  waitForEmptyQueues()

asyncTest "Bloomfilter blocking":
  let sendTopic1 = [byte 0x12, 0, 0, 0]
  let sendTopic2 = [byte 0x34, 0, 0, 0]
  let filterTopics = @[[byte 0x34, 0, 0, 0],[byte 0x56, 0, 0, 0]]
  let payload = repeat(byte 0, 10)
  var f: Future[int] = newFuture[int]()
  proc handler(msg: ReceivedMessage) =
    check msg.decoded.payload == payload
    f.complete(1)
  var filter = node1.subscribeFilter(newFilter(topics = filterTopics), some(handler))
  await node1.setBloomFilter(node1.filtersToBloom())

  check true == node2.postMessage(ttl = 1, topic = sendTopic1, payload = payload)

  await f or sleepAsync(300)
  check:
    f.finished == false
    node1.protocolState(Whisper).queue.items.len == 0
    node2.protocolState(Whisper).queue.items.len == 1

  f = newFuture[int]()
  waitForEmptyQueues()

  check true == node2.postMessage(ttl = 1, topic = sendTopic2, payload = payload)

  await f or sleepAsync(300)
  check:
    f.finished == true
    f.read() == 1
    node1.protocolState(Whisper).queue.items.len == 1
    node2.protocolState(Whisper).queue.items.len == 1

    node1.unsubscribeFilter(filter) == true

  await node1.setBloomFilter(fullBloom())

  waitForEmptyQueues()

asyncTest "PoW blocking":
  let topic = [byte 0, 0, 0, 0]
  let payload = repeat(byte 0, 10)
  await node1.setPowRequirement(1.0)
  check true == node2.postMessage(ttl = 1, topic = topic, payload = payload)
  await sleepAsync(300)
  check:
    node1.protocolState(Whisper).queue.items.len == 0
    node2.protocolState(Whisper).queue.items.len == 1

  waitForEmptyQueues()

  await node1.setPowRequirement(0.0)
  check true == node2.postMessage(ttl = 1, topic = topic, payload = payload)
  await sleepAsync(300)
  check:
    node1.protocolState(Whisper).queue.items.len == 1
    node2.protocolState(Whisper).queue.items.len == 1

  waitForEmptyQueues()

asyncTest "Queue pruning":
  let topic = [byte 0, 0, 0, 0]
  let payload = repeat(byte 0, 10)
  for i in countdown(10, 1):
    check true == node2.postMessage(ttl = i.uint32, topic = topic,
                                    payload = payload)
  check node2.protocolState(Whisper).queue.items.len == 10

  await sleepAsync(300)
  check:
    node1.protocolState(Whisper).queue.items.len == 10

  await sleepAsync(1000)
  check:
    node1.protocolState(Whisper).queue.items.len == 0
    node2.protocolState(Whisper).queue.items.len == 0

asyncTest "Light node posting":
  let topic = [byte 0, 0, 0, 0]
  node1.setLightNode(true)
  var result = node1.postMessage(ttl = 2, topic = topic, payload = repeat(byte 0, 10))

  check:
    result == false
    node1.protocolState(Whisper).queue.items.len == 0

  node1.setLightNode(false)

asyncTest "P2P":
  let topic = [byte 0, 0, 0, 0]
  var f: Future[int] = newFuture[int]()
  proc handler(msg: ReceivedMessage) =
    check msg.decoded.payload == repeat(byte 4, 10)
    f.complete(1)

  var filter = node1.subscribeFilter(newFilter(topics = @[topic], allowP2P = true),
                                     some(handler))
  check:
    true == node1.setPeerTrusted(toNodeId(node2.keys.pubkey))
    true == node2.postMessage(ttl = 2, topic = topic,
                              payload = repeat(byte 4, 10),
                              targetPeer = some(toNodeId(node1.keys.pubkey)))

  await f or sleepAsync(300)
  check:
    f.finished == true
    f.read() == 1
    node1.protocolState(Whisper).queue.items.len == 0
    node2.protocolState(Whisper).queue.items.len == 0

    node1.unsubscribeFilter(filter) == true
