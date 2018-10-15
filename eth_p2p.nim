#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import
  tables, deques, macros, sets, algorithm, hashes, times,
  random, options, sequtils, typetraits, os,
  asyncdispatch2, asyncdispatch2/timer,
  rlp, ranges/[stackarrays, ptr_arith], nimcrypto, chronicles,
  eth_keys, eth_common,
  eth_p2p/[kademlia, discovery, auth, rlpxcrypt, enode]

export
  enode, kademlia, options

proc addProtocol(n: var EthereumNode, p: ProtocolInfo) =
  assert n.connectionState == ConnectionState.None
  let pos = lowerBound(n.rlpxProtocols, p)
  n.rlpxProtocols.insert(p, pos)
  n.rlpxCapabilities.insert(Capability(name: p.name, version: p.version), pos)

template addCapability*(n: var EthereumNode, Protocol: type) =
  addProtocol(n, Protocol.protocolInfo)

proc newEthereumNode*(keys: KeyPair,
                      address: Address,
                      networkId: uint,
                      chain: AbstractChainDB,
                      clientId = clientId,
                      addAllCapabilities = true): EthereumNode =
  new result
  result.keys = keys
  result.networkId = networkId
  result.clientId = clientId
  result.rlpxProtocols.newSeq 0
  result.rlpxCapabilities.newSeq 0
  result.address = address
  result.connectionState = ConnectionState.None

  if addAllCapabilities:
    for p in rlpxProtocols:
      result.addProtocol(p)

proc processIncoming(server: StreamServer,
                     remote: StreamTransport): Future[void] {.async, gcsafe.} =
  var node = getUserData[EthereumNode](server)
  let peerfut = node.rlpxAccept(remote)
  yield peerfut
  if not peerfut.failed:
    let peer = peerfut.read()
    echo "TODO: Add peer to the pool..."
  else:
    echo "Could not establish connection with incoming peer ",
         $remote.remoteAddress()
    remote.close()

proc startListening*(node: EthereumNode) =
  info "RLPx listener up", self = initENode(node.keys.pubKey, node.address)
  let ta = initTAddress(node.address.ip, node.address.tcpPort)
  if node.listeningServer == nil:
    node.listeningServer = createStreamServer(ta, processIncoming,
                                              {ReuseAddr},
                                              udata = cast[pointer](node))
  node.listeningServer.start()

proc connectToNetwork*(node: EthereumNode,
                       bootstrapNodes: seq[ENode],
                       startListening = true,
                       enableDiscovery = true) {.async.} =
  assert node.connectionState == ConnectionState.None

  node.connectionState = Connecting
  node.discovery = newDiscoveryProtocol(node.keys.seckey,
                                        node.address,
                                        bootstrapNodes)

  node.peerPool = newPeerPool(node, node.chain, node.networkId,
                              node.keys, node.discovery,
                              node.clientId, node.address.tcpPort)

  if startListening:
    eth_p2p.startListening(node)

  node.protocolStates.newSeq(rlpxProtocols.len)
  for p in node.rlpxProtocols:
    if p.networkStateInitializer != nil:
      node.protocolStates[p.index] = p.networkStateInitializer(node)

  if startListening:
    node.listeningServer.start()

  if enableDiscovery:
    node.discovery.open()
    await node.discovery.bootstrap()
  else:
    info "Disovery disabled"

  node.peerPool.start()

  while node.peerPool.connectedNodes.len == 0:
    debug "Waiting for more peers", peers = node.peerPool.connectedNodes.len
    await sleepAsync(500)

proc stopListening*(node: EthereumNode) =
  node.listeningServer.stop()

iterator peers*(node: EthereumNode): Peer =
  for peer in node.peerPool.peers:
    yield peer

iterator peers*(node: EthereumNode, Protocol: type): Peer =
  for peer in node.peerPool.peers(Protocol):
    yield peer

iterator randomPeers*(node: EthereumNode, maxPeers: int): Peer =
  # TODO: this can be implemented more efficiently

  # XXX: this doesn't compile, why?
  # var peer = toSeq node.peers
  var peers = newSeqOfCap[Peer](node.peerPool.connectedNodes.len)
  for peer in node.peers: peers.add(peer)

  shuffle(peers)
  for i in 0 ..< min(maxPeers, peers.len):
    yield peers[i]

proc randomPeer*(node: EthereumNode): Peer =
  let peerIdx = random(node.peerPool.connectedNodes.len)
  var i = 0
  for peer in node.peers:
    if i == peerIdx: return peer
    inc i

