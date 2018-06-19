#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import asyncdispatch2, eth_keys
import peer_pool, discovery, enode, auth, rlpx

type
  P2PServer* = ref object
    server: StreamServer
    chainDb: AsyncChainDb
    keyPair: KeyPair
    address: Address
    networkId: int
    clientId: string
    discovery: DiscoveryProtocol
    peerPool: PeerPool

proc processIncoming(server: StreamServer,
                     remote: StreamTransport): Future[void] {.async, gcsafe.} =
  var p2p = getUserData[P2PServer](server)
  let peerfut = remote.rlpxAccept(p2p.keyPair, p2p.clientId)
  yield peerfut
  if not peerfut.failed:
    let peer = peerfut.read()
    echo "TODO: Add peer to the pool..."
  else:
    echo "Could not establish connection with incoming peer ",
         $remote.remoteAddress()
    remote.close()

proc newP2PServer*(keyPair: KeyPair, address: Address, chainDb: AsyncChainDB,
                   bootstrapNodes: openarray[ENode], clientId: string,
                   networkId: int): P2PServer =
  result.new()
  result.chainDb = chainDb
  result.keyPair = keyPair
  result.address = address
  result.clientId = clientId
  result.networkId = networkId
  result.discovery = newDiscoveryProtocol(keyPair.seckey, address,
                                          bootstrapNodes)
  result.peerPool = newPeerPool(chainDb, networkId, keyPair, result.discovery,
                                clientId, address.tcpPort)

  let ta = initTAddress(address.ip, address.tcpPort)
  result.server = createStreamServer(ta, processIncoming, {ReuseAddr},
                                     udata = result)

proc start*(s: P2PServer) =
  s.server.start()

proc stop*(s: P2PServer) =
  s.server.stop()
