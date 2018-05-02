import peer_pool, discovery, async, asyncnet
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
                bootstrapNodes: openarray[string], networkId: int): Server =
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
  discard # Perform hanshake
  discard # Create Peer
  discard # Add Peer to PeerPool

async def receive_handshake(
    self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
  # Use reader to read the auth_init msg until EOF
  msg = await reader.read(ENCRYPTED_AUTH_MSG_LEN)

  # Use HandshakeResponder.decode_authentication(auth_init_message) on auth init msg
  try:
    ephem_pubkey, initiator_nonce, initiator_pubkey = decode_authentication(
      msg, self.privkey)
  # Try to decode as EIP8
  except DecryptionError:
    msg_size = big_endian_to_int(msg[:2])
    remaining_bytes = msg_size - ENCRYPTED_AUTH_MSG_LEN + 2
    msg += await reader.read(remaining_bytes)
    ephem_pubkey, initiator_nonce, initiator_pubkey = decode_authentication(
      msg, self.privkey)

  # Get remote's address: IPv4 or IPv6
  ip, port, *_ = writer.get_extra_info("peername")
  remote_address = Address(ip, port)

  # Create `HandshakeResponder(remote: kademlia.Node, privkey: datatypes.PrivateKey)` instance
  initiator_remote = Node(initiator_pubkey, remote_address)
  responder = HandshakeResponder(initiator_remote, self.privkey)

  # Call `HandshakeResponder.create_auth_ack_message(nonce: bytes)` to create the reply
  responder_nonce = secrets.token_bytes(HASH_LEN)
  auth_ack_msg = responder.create_auth_ack_message(nonce=responder_nonce)
  auth_ack_ciphertext = responder.encrypt_auth_ack_message(auth_ack_msg)

  # Use the `writer` to send the reply to the remote
  writer.write(auth_ack_ciphertext)
  await writer.drain()

  # Call `HandshakeResponder.derive_shared_secrets()` and use return values to create `Peer`
  aes_secret, mac_secret, egress_mac, ingress_mac = responder.derive_secrets(
    initiator_nonce=initiator_nonce,
    responder_nonce=responder_nonce,
    remote_ephemeral_pubkey=ephem_pubkey,
    auth_init_ciphertext=msg,
    auth_ack_ciphertext=auth_ack_ciphertext
  )

  # Create and register peer in peer_pool
  eth_peer = ETHPeer(
    remote=initiator_remote, privkey=self.privkey, reader=reader,
    writer=writer, aes_secret=aes_secret, mac_secret=mac_secret,
    egress_mac=egress_mac, ingress_mac=ingress_mac, chaindb=self.chaindb,
    network_id=self.network_id
  )
  self.peer_pool.add_peer(eth_peer)


def decode_authentication(ciphertext: bytes,
              privkey: datatypes.PrivateKey
              ) -> Tuple[datatypes.PublicKey, bytes, datatypes.PublicKey]:
  """
  Decrypts and decodes the ciphertext msg.
  Returns the initiator's ephemeral pubkey, nonce, and pubkey.
  """
  if len(ciphertext) < ENCRYPTED_AUTH_MSG_LEN:
    raise ValueError("Auth msg too short: {}".format(len(ciphertext)))
  elif len(ciphertext) == ENCRYPTED_AUTH_MSG_LEN:
    sig, initiator_pubkey, initiator_nonce, _ = decode_auth_plain(
      ciphertext, privkey)
  else:
    sig, initiator_pubkey, initiator_nonce, _ = decode_auth_eip8(
      ciphertext, privkey)

  # recover initiator ephemeral pubkey from sig
  #   S(ephemeral-privk, ecdh-shared-secret ^ nonce)
  shared_secret = ecdh_agree(privkey, initiator_pubkey)

  ephem_pubkey = sig.recover_public_key_from_msg_hash(
    sxor(shared_secret, initiator_nonce))

  return ephem_pubkey, initiator_nonce, initiator_pubkey


proc run(s: Server) {.async.} =
  s.socket = newAsyncSocket()
  s.socket.setSockOpt(OptReuseAddr, true)
  s.socket.setSockOpt(OptReusePort, true)
  s.socket.bindAddr(s.address.tcpPort)
  s.socket.listen()

  while s.isRunning:
    let (address, client) = await s.socket.acceptAddr()
    asyncCheck s.receiveHandshake(address, client)

proc start*(s: Server) =
  if s.isRunning:
    asyncCheck s.run()

proc stop*(s: Server) =
  if s.isRunning:
    s.socket.close()
    s.socket = nil
    # s.peerPool.stop() # XXX

