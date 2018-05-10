import peer_pool, discovery, enode, async, asyncnet, auth, rlpx, net
import eth_keys

type Server* = ref object
  socket: AsyncSocket
  chainDb: AsyncChainDb
  keyPair: KeyPair
  address: Address
  networkId: int
  discovery: DiscoveryProtocol
  peerPool: PeerPool

proc newServer*(keyPair: KeyPair, address: Address, chainDb: AsyncChainDB,
                bootstrapNodes: openarray[ENode], networkId: int): Server =
  result.new()
  result.chainDb = chainDb
  result.keyPair = keyPair
  result.address = address
  result.networkId = networkId
  # TODO: bootstrap_nodes should be looked up by network_id.
  result.discovery = newDiscoveryProtocol(keyPair.seckey, address, bootstrapNodes)
  result.peerPool = newPeerPool(chainDb, networkId, keyPair, result.discovery)

proc isRunning(s: Server): bool {.inline.} = not s.socket.isNil

proc receiveHandshake(s: Server, address: string, remote: AsyncSocket) {.async.} =
  let p = await rlpxConnectIncoming(s.keyPair, s.address.tcpPort, parseIpAddress(address), remote)
  if not p.isNil:
    echo "TODO: Add peer to the pool..."
  else:
    echo "Could not establish connection with incoming peer"

proc run(s: Server) {.async.} =
  s.socket = newAsyncSocket()
  s.socket.setSockOpt(OptReuseAddr, true)
  s.socket.bindAddr(s.address.tcpPort)
  s.socket.listen()

  while s.isRunning:
    let (address, client) = await s.socket.acceptAddr()
    asyncCheck s.receiveHandshake(address, client)

proc start*(s: Server) =
  if not s.isRunning:
    asyncCheck s.run()

proc stop*(s: Server) =
  if s.isRunning:
    s.socket.close()
    s.socket = nil
    # s.peerPool.stop() # XXX
