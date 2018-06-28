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

const clientId = "nim-eth-p2p/0.0.1"

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

proc test() {.async.} =
  let kp = newKeyPair()
  let address = localAddress(20301)

  let s = newP2PServer(kp, address, nil, [], clientId, 1)
  s.start()

  let n = newNode(initENode(kp.pubKey, address))
  let peer = await rlpxConnect(n, newKeyPair(), Port(1234), clientId)

  doAssert(not peer.isNil)

echo "Testing without Snappy"
waitFor test()

proc testSnappy() {.async.} =
  let kp = newKeyPair()
  let address = localAddress(20302)

  let s = newP2PServer(kp, address, nil, [], clientId, 1, true)
  s.start()

  let n = newNode(initENode(kp.pubKey, address))
  let peer = await rlpxConnect(n, newKeyPair(), Port(12345), clientId)

  doAssert(not peer.isNil)

echo "-------------------------------"
echo "Testing with Snappy"
waitFor testSnappy()
