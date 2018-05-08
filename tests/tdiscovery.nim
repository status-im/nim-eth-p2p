import ../ethp2p/[discovery, kademlia, peer_pool, enode]
import eth_keys, net, asyncdispatch, sequtils

import logging, byteutils

addHandler(newConsoleLogger())

proc startDiscoveryNode(privKey: PrivateKey, address: Address, bootnodes: seq[ENode]): Future[DiscoveryProtocol] {.async.} =
  result = newDiscoveryProtocol(privKey, address, bootnodes)
  result.open()
  await result.bootstrap()

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

let
  bootNodeKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
  bootNodeAddr = localAddress(20301)
  bootENode = initENode(bootNodeKey.getPublicKey, bootNodeAddr)

  nodeKeys = [
    initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618"),
    initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a619"),
    initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a620")
  ]

proc nodeIdInNodes(id: NodeId, nodes: openarray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

proc test() {.async.} =
  let bootNode = await startDiscoveryNode(bootNodeKey, bootNodeAddr, @[])

  var nodeAddrs = newSeqOfCap[Address](nodeKeys.len)
  for i in 0 ..< nodeKeys.len: nodeAddrs.add(localAddress(20302 + i))

  var nodes = await all(zip(nodeKeys, nodeAddrs).mapIt(startDiscoveryNode(it.a, it.b, @[bootENode])))
  nodes.add(bootNode)

  for i in nodes:
    for j in nodes:
      if j != i:
        doAssert(nodeIdInNodes(i.thisNode.id, j.randomNodes(nodes.len - 1)))

waitFor test()
