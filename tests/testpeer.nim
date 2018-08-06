import asyncdispatch2, eth_keys, eth_common, rlp, chronicles, nimcrypto, stint
import peer, protocols, eth, enode

const
  NodeKey = "1b5b2a9c891067139c2aac53f66a84e2888ce494407a21c662dc546150e7e170"
  # enode://425f2261ef52010ed833bdbebbc67c36dfc208c0330e2c248fadef3feeb291c677265289bf64437055116b7d1dc3f78be5122d0041f021c01a501b876c664d4f@[::]:30303
  ENodeAddress = "enode://410a034fbd91e872cbe52a5fb5bec1f030d4239dab35efbdf53b6a3f09f42a84965f0d5c76c44d42b791339ff249675ec7fc656d69d10cb95b315a1136f6634e@192.168.2.10:30303"
  GenesisHash = "D4E56740F876AEF8C010B86A40D5F56745A118D0906A34E69AEC8C0DB1CB8FA3"

proc getInterface(en: EthereumNode, peer: Peer, epcap: EPeerCap): EInterface =
  var
    version: int
    network: int
    totalDifficulty: UInt256
    bestHash: Hash256
    genesisHash: Hash256

  var currentTotalDifficulty = 0.u256
  var currentBestHash: Hash256
  var currentGenesisHash: Hash256

  var hash = fromHex(GenesisHash)
  copyMem(addr currentGenesisHash, addr hash[0], 32)

  proc handshake(peer: Peer): Future[bool] {.async.} =
    # Sending `Status` message to remote peer.
    let res = await peer.sendStatus(epcap, en.network, currentTotalDifficulty,
                                    currentBestHash, currentGenesisHash)
    if not res: return false

    # Waiting for `Status` message from remote peer.
    var msg = await peer.getMessage(epcap)

    # Converting synchronized command id back to protocol message id.
    var ethid = epcap.ethGetCmd(msg.id)

    if msg.id == MsgBad or msg.id == MsgDisconnect:
      ## Received message is rather incorrect or disconnect.
      result = false
    else:
      if ethid == MsgStatus:
        result = true
        # Decoding `Status` message frame.
        if (not msg.data.isList()) or (msg.data.listLen() != 5):
          debug "Malformed status message received", peer = $peer,
                                                     isList = msg.data.isList(),
                                                 listLength = msg.data.listLen()
          result = false

        if not result: return

        try:
          msg.data.enterList()
          version = msg.data.read(int)
          network = msg.data.read(int)
          totalDifficulty = msg.data.read(UInt256)
          bestHash = msg.data.read(Hash256)
          genesisHash = msg.data.read(Hash256)
        except:
          debug "Malformed status message received", peer = $peer
          result = false

        if not result: return

        # Verification of received data from `Status` message frame.
        if version != epcap.version():
          debug "Sub-protocol version did not match", peer = $peer,
                                                      remoteVersion = $version,
                                                   localVersion = $epcap.version
          await peer.disconnect(UselessPeer)
          return false

        # Remote network id must be equal to our network id
        if network != en.network:
          debug "Different network id specified", peer = $peer,
                                                  remoteNetwork = network,
                                                  localNetwork = en.network
          await peer.disconnect(UselessPeer)
          return false

        # Remote Genesis must be equal to our Genesis
        if genesisHash != currentGenesisHash:
          debug "Genesis hash did not match", peer = $peer,
                                              remoteGenesis = $genesisHash,
                                              localGenesis = $currentGenesisHash
          await peer.disconnect(UselessPeer)
          return false

        debug "Ethereum Protocol started", peer = $peer,
                                           version = $epcap.version
        result = true
      else:
        # There must be no other messages, except `Status` message.
        debug "Incorrect message received", peer = $peer, msgId = $msg.id
        result = false

  proc run(peer: Peer) {.async.} =
    while true:
      var msg = await peer.getMessage(epcap)
      if msg.id == MsgBad:
        # Remote peer sent malformed message or get disconnected without reason.
        # You don't need to close peer here, this is just notification so you
        # can break your cycle.
        debug "Sub-protocol received notification", peer = $peer
        break
      elif msg.id == MsgDisconnect:
        # Remote peer send `Disconnect` message with a reason.
        # You don't need to close peer here, this is just notification so you
        # can break your cycle.
        debug "Sub-protocol received disconnect notification", peer = $peer
        break
      else:
        # Here we can get any message specific exactly to this protocol.
        let ethid = epcap.ethGetCmd(msg.id)
        if ethid == -1:
          # Received message with id, which is not related to protocol
          debug "Sub-protocol received incorrect message", peer = $peer,
                                                           msgid = $msg.id
          # peer.disconnect() will do `peer.close()` for us
          await peer.disconnect(BreachOfProtocol)
          break
        else:
          debug "Sub-protocol received message", peer = $peer,
                                                 msgid = $msg.id,
                                                 ethid = $ethid
          if ethid == MsgGetBlockHeaders:
            debug "Received MsgGetBlockHeaders", peer = $peer
          elif ethid == MsgGetBlockBodies:
            debug "Received MsgGetBlockBodies", peer = $peer
          elif ethid == MsgGetNodeData:
            debug "Received MsgGetNodeData", peer = $peer
          elif ethid == MsgGetReceipts:
            debug "Received MsgGetReceipts", peer = $peer

  new result
  result.handshake = handshake
  result.run = run

proc test() {.async.} =
  var en = newEthereumNode(1, initPrivateKey(NodeKey))
  en.registerProtocol(initECap("eth", 63), getInterface)
  let peer = await connect(en, ENodeAddress)
  await sleepAsync(1000)
  var time = await peer.ping()
  echo "PONG RECEIVED in ", time, "ms"
  await sleepAsync(1000000)

when isMainModule:
  waitFor test()
