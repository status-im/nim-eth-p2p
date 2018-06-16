import
  eth_keys, net, asyncdispatch, sequtils,
  ../eth_p2p/[discovery, kademlia, peer_pool, enode, server, rlpx]

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))


proc test() {.async.} =
  let kp = newKeyPair()
  let address = localAddress(20301)

  let s = newServer(kp, address, nil, [], 1)
  s.start()

  await sleepAsync(500)

  let n = newNode(initENode(kp.pubKey, address))
  let peer = await rlpxConnect(newKeyPair(), Port(1234), n)

  doAssert(not peer.isNil)

waitFor test()
