#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import logging, tables, times, random
import eth_keys, asyncdispatch2
import discovery, rlpx, kademlia

type
  PeerPool* = ref object
    keyPair: KeyPair
    networkId: int
    minPeers: int
    clientId: string
    discovery: DiscoveryProtocol
    lastLookupTime: float
    connectedNodes: Table[Node, Peer]
    running: bool
    listenPort*: Port

  AsyncChainDb* = ref object # TODO: This should be defined elsewhere

# class PeerPool:
# PeerPool attempts to keep connections to at least min_peers on the given network.

const
  lookupInterval = 5
  connectLoopSleepMs = 2000

proc newPeerPool*(chainDb: AsyncChainDb, networkId: int, keyPair: KeyPair,
                  discovery: DiscoveryProtocol, clientId: string,
                  listenPort = Port(30303), minPeers = 10): PeerPool =
  result.new()
  result.keyPair = keyPair
  result.minPeers = minPeers
  result.networkId = networkId
  result.discovery = discovery
  result.connectedNodes = initTable[Node, Peer]()
  result.listenPort = listenPort

template ensureFuture(f: untyped) = asyncCheck f

proc nodesToConnect(p: PeerPool): seq[Node] {.inline.} =
  p.discovery.randomNodes(p.minPeers)

# def subscribe(self, subscriber: PeerPoolSubscriber) -> None:
#   self._subscribers.append(subscriber)
#   for peer in self.connected_nodes.values():
#     subscriber.register_peer(peer)

# def unsubscribe(self, subscriber: PeerPoolSubscriber) -> None:
#   if subscriber in self._subscribers:
#     self._subscribers.remove(subscriber)

proc stopAllPeers(p: PeerPool) {.async.} =
  info "Stopping all peers ..."
  # TODO: ...
  # await asyncio.gather(
  #   *[peer.stop() for peer in self.connected_nodes.values()])

# async def stop(self) -> None:
#   self.cancel_token.trigger()
#   await self.stop_all_peers()

proc connect(p: PeerPool, remote: Node): Future[Peer] {.async.} =
  ## Connect to the given remote and return a Peer instance when successful.
  ## Returns nil if the remote is unreachable, times out or is useless.
  if remote in p.connectedNodes:
    debug "Skipping ", remote, "; already connected to it"
    return nil

  result = await remote.rlpxConnect(p.keyPair, p.listenPort, p.clientId)

  # expected_exceptions = (
  #   UnreachablePeer, TimeoutError, PeerConnectionLost, HandshakeFailure)
  # try:
  #   self.logger.debug("Connecting to %s...", remote)
  #   peer = await wait_with_token(
  #     handshake(remote, self.privkey, self.peer_class, self.chaindb, self.network_id),
  #     token=self.cancel_token,
  #     timeout=HANDSHAKE_TIMEOUT)
  #   return peer
  # except OperationCancelled:
  #   # Pass it on to instruct our main loop to stop.
  #   raise
  # except expected_exceptions as e:
  #   self.logger.debug("Could not complete handshake with %s: %s", remote, repr(e))
  # except Exception:
  #   self.logger.exception("Unexpected error during auth/p2p handshake with %s", remote)
  # return None

proc lookupRandomNode(p: PeerPool) {.async.} =
  # This method runs in the background, so we must catch OperationCancelled
  # ere otherwise asyncio will warn that its exception was never retrieved.
  try:
    discard await p.discovery.lookupRandom()
  except: # OperationCancelled
    discard
  p.lastLookupTime = epochTime()

proc getRandomBootnode(p: PeerPool): seq[Node] =
  @[p.discovery.bootstrapNodes.rand()]

proc peerFinished(p: PeerPool, peer: Peer) =
  ## Remove the given peer from our list of connected nodes.
  ## This is passed as a callback to be called when a peer finishes.
  p.connectedNodes.del(peer.remote)

proc run(p: Peer, completionHandler: proc() = nil) {.async.} =
  # TODO: This is a stub that should be implemented in rlpx.nim
  await sleepAsync(20000) # sleep 20 sec
  if not completionHandler.isNil: completionHandler()

proc connectToNodes(p: PeerPool, nodes: seq[Node]) {.async.} =
  for node in nodes:
    # TODO: Consider changing connect() to raise an exception instead of
    # returning None, as discussed in
    # https://github.com/ethereum/py-evm/pull/139#discussion_r152067425
    let peer = await p.connect(node)
    if not peer.isNil:
      info "Successfully connected to ", peer
      ensureFuture peer.run() do():
        p.peerFinished(peer)

      p.connectedNodes[peer.remote] = peer
      # for subscriber in self._subscribers:
      #   subscriber.register_peer(peer)
      if p.connectedNodes.len >= p.minPeers:
        return

proc maybeConnectToMorePeers(p: PeerPool) {.async.} =
  ## Connect to more peers if we're not yet connected to at least self.minPeers.
  if p.connectedNodes.len >= p.minPeers:
    debug "Already connected to enough peers: ", p.connectedNodes, "; sleeping"
    return

  if p.lastLookupTime + lookupInterval < epochTime():
    ensureFuture p.lookupRandomNode()

  await p.connectToNodes(p.nodesToConnect())

  # In some cases (e.g ROPSTEN or private testnets), the discovery table might
  # be full of bad peers, so if we can't connect to any peers we try a random
  # bootstrap node as well.
  if p.connectedNodes.len == 0:
    await p.connectToNodes(p.getRandomBootnode())

proc run(p: PeerPool) {.async.} =
  info "Running PeerPool..."
  p.running = true
  while p.running:
    var dropConnections = false
    try:
      await p.maybeConnectToMorePeers()
    except:
      # Most unexpected errors should be transient, so we log and restart from
      # scratch.
      error "Unexpected error, restarting"
      dropConnections = true

    if dropConnections:
      await p.stopAllPeers()

    await sleepAsync(connectLoopSleepMs)

proc start*(p: PeerPool) =
  if not p.running:
    asyncCheck p.run()


# @property
# def peers(self) -> List[BasePeer]:
#   peers = list(self.connected_nodes.values())
#   # Shuffle the list of peers so that dumb callsites are less likely to send
#   # all requests to
#   # a single peer even if they always pick the first one from the list.
#   random.shuffle(peers)
#   return peers

# async def get_random_peer(self) -> BasePeer:
#   while not self.peers:
#     self.logger.debug("No connected peers, sleeping a bit")
#     await asyncio.sleep(0.5)
#   return random.choice(self.peers)

