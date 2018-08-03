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
import eth_p2p

const clientId = "nim-eth-p2p/0.0.1"

rlpxProtocol dmy, 1: # Rlpx would be useless with no subprotocols. So we define a dummy proto
  proc foo(peer: Peer)

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

proc test() {.async.} =
  let node1Keys = newKeyPair()
  let node1Address = localAddress(30303)
  var node1 = newEthereumNode(node1Keys, node1Address, 1, nil)
  node1.startListening()

  let node2Keys = newKeyPair()
  var node2 = newEthereumNode(node2Keys, localAddress(30304), 1, nil)

  let node1AsRemote = newNode(initENode(node1Keys.pubKey, node1Address))
  let peer = await node2.rlpxConnect(node1AsRemote)

  doAssert(not peer.isNil)

waitFor test()
