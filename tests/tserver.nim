#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import sequtils
import eth_keys, asyncdispatch2
import eth_p2p/[discovery, kademlia, peer_pool, enode, server, rlpx]

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

proc test() {.async.} =
  let kp = newKeyPair()
  let address = localAddress(20301)

  let s = newP2PServer(kp, address, nil, [], 1)
  s.start()

  let n = newNode(initENode(kp.pubKey, address))
  let peer = await rlpxConnect(n, newKeyPair(), Port(1234))

  doAssert(not peer.isNil)

waitFor test()
