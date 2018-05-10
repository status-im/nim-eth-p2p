import ../ethp2p/[discovery, kademlia, peer_pool, enode, server, rlpx]
import eth_keys, net, asyncdispatch, sequtils

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
  let peer = await rlpxConnect(newKeyPair(), n)

  doAssert(not peer.isNil)

waitFor test()
