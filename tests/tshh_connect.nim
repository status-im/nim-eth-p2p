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
node1.addCapability shh

var node2 = newEthereumNode(keys2, localAddress(30304), 1, nil,
                            addAllCapabilities = false,
                            useCompression = useCompression)
node2.addCapability shh

template waitForEmptyQueues() =
  while node1.protocolState(shh).queue.items.len != 0 or
        node2.protocolState(shh).queue.items.len != 0: poll()

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
  node1.initProtocolStates()
  node2.initProtocolStates()
  node2.startListening()
  discard waitFor node1.rlpxConnect(newNode(initENode(node2.keys.pubKey,
                                                      node2.address)))

asyncTest "Filters with encryption and signing":
  let encryptKeyPair = newKeyPair()
  let signKeyPair = newKeyPair()
  var symKey: SymKey
  let topic = [byte 0x12, 0, 0, 0]
  var filters: seq[string] = @[]

  proc handler1(payload: Bytes) =
    check payload == repeat(byte 1, 10) or payload == repeat(byte 2, 10)
  proc handler2(payload: Bytes) =
    check payload == repeat(byte 2, 10)
  proc handler3(payload: Bytes) =
    check payload == repeat(byte 3, 10) or payload == repeat(byte 4, 10)
  proc handler4(payload: Bytes) =
    check payload == repeat(byte 4, 10)

  # Filters
  # filter for encrypted asym
  filters.add(node1.subscribeFilter(newFilter(privateKey = some(encryptKeyPair.seckey),
                                              topics = @[topic]), handler1))
  # filter for encrypted asym + signed
  filters.add(node1.subscribeFilter(newFilter(some(signKeyPair.pubkey),
                                              privateKey = some(encryptKeyPair.seckey),
                                              topics = @[topic]), handler2))
  # filter for encrypted sym
  filters.add(node1.subscribeFilter(newFilter(symKey = some(symKey),
                                              topics = @[topic]), handler3))
  # filter for encrypted sym + signed
  filters.add(node1.subscribeFilter(newFilter(some(signKeyPair.pubkey),
                                              symKey = some(symKey),
                                              topics = @[topic]), handler4))
  # Messages
  # encrypted asym
  node2.postMessage(some(encryptKeyPair.pubkey), ttl = 5, topic = topic,
                    payload = repeat(byte 1, 10))
  # encrypted asym + signed
  node2.postMessage(some(encryptKeyPair.pubkey), src = some(signKeyPair.seckey),
                    ttl = 4, topic = topic, payload = repeat(byte 2, 10))
  # encrypted sym
  node2.postMessage(symKey = some(symKey), ttl = 3, topic = topic,
                    payload = repeat(byte 3, 10))
  # encrypted sym + signed
  node2.postMessage(symKey = some(symKey), src = some(signKeyPair.seckey),
                    ttl = 2, topic = topic, payload = repeat(byte 4, 10))

  check node2.protocolState(shh).queue.items.len == 4

  # XXX: improve the dumb sleep
  await sleepAsync(300)
  check node1.protocolState(shh).queue.items.len == 4

  for filter in filters:
    check node1.unsubscribeFilter(filter) == true

  waitForEmptyQueues()

asyncTest "Filters with topics":
  check:
    1 == 1

asyncTest "Filters with PoW":
  check:
    1 == 1

asyncTest "Bloomfilter blocking":
  let sendTopic1 = [byte 0x12, 0, 0, 0]
  let sendTopic2 = [byte 0x34, 0, 0, 0]
  let filterTopics = @[[byte 0x34, 0, 0, 0],[byte 0x56, 0, 0, 0]]
  proc handler(payload: Bytes) = discard
  var filter = node1.subscribeFilter(newFilter(topics = filterTopics), handler)
  await node1.setBloomFilter(node1.filtersToBloom())

  node2.postMessage(ttl = 1, topic = sendTopic1, payload = repeat(byte 0, 10))
  # XXX: improve the dumb sleep
  await sleepAsync(300)
  check:
    node1.protocolState(shh).queue.items.len == 0
    node2.protocolState(shh).queue.items.len == 1

  waitForEmptyQueues()

  node2.postMessage(ttl = 1, topic = sendTopic2, payload = repeat(byte 0, 10))
  # XXX: improve the dumb sleep
  await sleepAsync(300)
  check:
    node1.protocolState(shh).queue.items.len == 1
    node2.protocolState(shh).queue.items.len == 1

  await node1.setBloomFilter(fullBloom())

  waitForEmptyQueues()

asyncTest "PoW blocking":
  let topic = [byte 0, 0, 0, 0]
  await node1.setPowRequirement(1.0)
  node2.postMessage(ttl = 1, topic = topic, payload = repeat(byte 0, 10))
  await sleepAsync(300)
  check:
    node1.protocolState(shh).queue.items.len == 0
    node2.protocolState(shh).queue.items.len == 1

  waitForEmptyQueues()

  await node1.setPowRequirement(0.0)
  node2.postMessage(ttl = 1, topic = topic, payload = repeat(byte 0, 10))
  await sleepAsync(300)
  check:
    node1.protocolState(shh).queue.items.len == 1
    node2.protocolState(shh).queue.items.len == 1

  waitForEmptyQueues()

asyncTest "Queue pruning":
  let topic = [byte 0, 0, 0, 0]
  for i in countdown(10, 1):
    node2.postMessage(ttl = i.uint32, topic = topic, payload = repeat(byte 0, 10))

  await sleepAsync(300)
  check:
    node1.protocolState(shh).queue.items.len == 10
    node2.protocolState(shh).queue.items.len == 10

  await sleepAsync(1000)
  check:
    node1.protocolState(shh).queue.items.len == 0
    node2.protocolState(shh).queue.items.len == 0

asyncTest "Lightnode":
  check:
    1 == 1

asyncTest "P2P":
  check:
    1 == 1
