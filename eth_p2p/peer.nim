#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

## This is alternative approach for Ethereum Networking.
##
## Approach is based on extending ``Peer`` functionality depending on protocols
## it supports. With such approach you can easily support LES and ETH protocols
## in one peer instance.
##
## Two mechanisms are introduced to handle incoming Ethereum frames, one is
## called ``subscribers`` and can be used via procedures
## ``subscribe/unsubscribe`` to watch for specific Ethereum message, and
## another is ``closure interfaces``, which can be used to implement logic code
## to process incoming messages. Closure interfaces are registered with global
## ``EthereumNode`` object and will be instantiated for every peer.
##
## Peer is taking care of disconnects, and can notify ``PeerPool`` about its
## death via `liveFuture`. So now you don't need to sleep in cycle in
## ``PeerPool`` code. ``PeerPool`` just needs to wait for peer's futures and
## it will know when one of the peers got disconnected and need to be replaced.
##
## All networking procedures are is taking care of timeouts:
## 1) Connection timeout
## 2) Authentication timeout
## 3) Handshake timeout
## 4) Request->Response timeout
##
## Introduced ``PeerMetrics`` object which will gather information about number
## of bytes received from specific peer. With information from ``PeerMetrics``
## you can make some kind of QOS to disconnect useless or slow peers.
##
## Every ``request->response`` message also store time of operation inside of
## message type ``EthereumMessage``, you can obtain it via ``elapsed`` field.
##
## **Subscribers**.
##
## Using subscribers you can register listener for any message in stream, but
## its more suitable to handle `request->response` pairs messages such as
## GetBlockHashes/BlockHashes, GetBlocks/Blocks, GetBlockHeaders/BlockHeaders,
## GetNodeData/NodeData, GetReceipts/Receipts. So if specification requires to
## handle `request->response` sequence, its easier to bundle both operations
## in one procedure, which first sends `request` and then subscribes a Future
## to response message id. If remote peer disconnected or sent
## malformed/incorrect message all subscribers will be notified with `MsgBad`
## empty message.
##
## You can see examples of `subscribers` usage in `eth.nim` code
##
## **Closure interfaces**.
##
## Interfaces is one more way to handle messages stream, you can use interfaces
## to handle all messages from peer's stream, but its more suitable to handle
## `announce` messages (like Transactions or NewBlock) and to handle requests
## from remote peer (GetBlockHashes, GetBlocks, GetBlockHeaders, GetBlockBodies,
## GetNodeData, GetReceipts).
## If remote peer disconnected or sent malformed/incorrect message interface
## will be notified with `MsgBad` empty message.
## In interface's `run` function you are running loop:
##
##   .. code-block::nim
##      proc run(peer: Peer) {.async.} =
##        while true:
##          # Waiting for message from remote `peer` and for protocol `epcap`.
##          var msg = await peer.getMessage(epcap)
##          if msg.id == MsgBad:
##            # Remote peer sent malformed message or get disconnected without
##            # reason.
##            break
##          elif msg.id == MsgDisconnect:
##            # Remote peer sent `Disconnect` message with a reason.
##            break
##          else:
##            # Here we can get any message specific exactly to this protocol.
##            # ethGetCmd() is procedure which performs check of message id
##            # according to protocol `epcap`. And if passed message is passed
##            # all checks, then zero based protocol message id will be returned
##            # (which will be equal to message id in specification).
##            let ethid = epcap.ethGetCmd(msg.id)
##            if ethid == -1:
##              # Received message with id, which is not related to protocol
##              await peer.disconnect(BreachOfProtocol)
##              break
##            else:
##           if ethid == MsgGetBlockHeaders:
##             # Received GetBlockHeaders
##             discard
##           elif ethid == MsgGetBlockBodies:
##             # Received GetBlockBodies.
##             discard
##           elif ethid == MsgGetNodeData:
##             # Received GetNodeData.
##             discard
##           elif ethid == MsgGetReceipts:
##             # received GetReceipts.
##             discard
##
## Every incoming message from remote peer will be delivered first to
## subscribers, and if there no subscribers for specific message id,
## it will be added to interface's message queue, so protocol interface can
## obtain it via ``getMessage()`` call.
##
## You can see examples of closure interfaces usage in `tests/testpeer.nim`.

import asyncdispatch2, eth_keys, ranges, rlp, nimcrypto, stint, eth_common
import protocols, kademlia, rlpxcrypt, auth, enode, chronicles

const
  PeerRecvBufferInitialSize* = 1024 ## Initial receiving buffer size for Peer.
  PeerSendBufferInitialSize* = 1024 ## Initial sending buffer size for Peer.
  ConnectTimeout* = 10000           ## Connection timeout in milliseconds.
  AuthenticationTimeout* = 10000    ## Authentication timeout in milliseconds.
  HandshakeTimeout* = 10000         ## devP2P handshake timeout in milliseconds.
  ResponseTimeout* = 60000          ## Initial peer's response waiting timeout
  MaxUInt24 = (not uint32(0)) shl 8 ## Maximum size of Ethereum devP2P frame.

const
  MsgTimeout* = -2
  MsgBad* = -1
  MsgHello* = 0
  MsgDisconnect* = 1
  MsgPing* = 2
  MsgPong* = 3

type
  PeerMetrics* = object
    ## Peer metrics used to calculate peer's performance (can be used in
    ## PeerPool to not use slow peers while sync)
    startTime*: uint64  ## Time in milliseconds when connection happens
    bytesCount*: uint64 ## Number of bytes received from peer

  ConnectionState* = enum
    ## Peer's connection state
    None,               ## Authenticating/Handshaking.
    Connected,          ## Connection established.
    Disconnecting,      ## `Disconnect` message was sent.
    Disconnected        ## Connection dropped.

  EthereumMessage* = object
    ## Ethereum devP2P message
    id*: int            ## Message ID.
    elapsed*: int       ## Time in milliseconds of request-response operation.
    data*: Rlp          ## Message RLP frame

  PeerFlags* = enum
    ## Peer's flags
    Incoming,      ## Peer was accepted.
    Outgoing       ## Peer was connected.

  DisconnectReason* = enum
    ## Ethereum devP2P disconnect reasons.
    DisconnectRequested,
    TcpError,
    BreachOfProtocol,
    UselessPeer,
    TooManyPeers,
    AlreadyConnected,
    IncompatibleProtocolVersion,
    NullNodeIdentityReceived,
    ClientQuitting,
    UnexpectedIdentity,
    SelfConnection,
    MessageTimeout,
    UnknownError12,
    UnknownError13,
    UnknownError14,
    UnknownError15,
    SubprotocolReason,
    UnknownError

  Peer* = ref object
    ## Peer's object
    transp*: StreamTransport                  ## peer's underlying transport
    node*: Node                               ## peer's p2p address
    sbuffer*: seq[byte]                       ## sending buffer
    rbuffer*: seq[byte]                       ## receiving buffer
    queues*: seq[AsyncQueue[EthereumMessage]] ## sub-protocol message queues
    ifaces: seq[EInterface]                   ## sub-protocol interfaces
    secrets*: SecretState                     ## peer's cryptographic secrets
    state*: ConnectionState                   ## current state
    flags*: set[PeerFlags]                    ## peer's flags
    version*: int                             ## peer's devP2P version
    clientId*: string                         ## peer's client identifier
    remotePort*: Port                         ## peer's TCP port to conect
    subscribers: array[256, Future[EthereumMessage]] ## peer's subscribers array
    allcaps*: ECapList                        ## peer's all capabilities list
    caps*: EPeerCapList                       ## peer's synchronized caps list
    liveFuture*: Future[void]                 ## peer's live future
    responseTimeout*: int                     ## peer's initial response timeout
    metrics*: PeerMetrics                     ## peer's metrics

  EthereumNode* = ref object
    netver*: int                              ## devP2P version
    clientId*: string                         ## client identifier
    port*: Port                               ## TCP port to connect
    caps*: ECapList                           ## available capabilities
    protocols*: seq[EProtocol]                ## available interfaces
    keys*: KeyPair                            ## security keys
    network*: int                             ## network id

  PeerException* = object of Exception
  PeerAddressException* = object of Exception
  PeerWriteIncomplete = object of PeerException

  EInterface* = ref object of RootRef
    ## Sub-protocol interface object definition
    handshake*: proc(peer: Peer): Future[bool]
      ## Callback which will be called to perform sub-protocol handshake.
      ## Callback must return ``true`` to signal that handshake was completed
      ## successfully or ``false`` on error.
    run*: proc(peer: Peer): Future[void]
      ## Callback which will be called to run message loop.
    liveFuture*: Future[void]
      ## Interface live future, which will be completed when ``run`` will be
      ## finished.

  EInterfaceProc* = proc(en: EthereumNode, peer: Peer,
                         proto: EPeerCap): EInterface
    ## Protocol interface initialization function

  EProtocol = object
    cap: ECap
    init: EInterfaceProc

proc checkIncomplete(w, e: int) =
  if w != e:
    raise newException(PeerWriteIncomplete, "Write operation incomplete!")

proc `$`*(peer: Peer): string =
  ## Return string representation of peer ``peer``.
  result = $peer.node

proc getReason*(reason: int): DisconnectReason =
  ## Convert integer reason code to ``DisconnectReason`` enum.
  if reason < int(low(DisconnectReason)) or
     reason > int(high(DisconnectReason)):
    result = UnknownError
  else:
    result = DisconnectReason(reason)

proc toIndex*(peer: Peer, cmdid: int): int =
  ## Get index in peer's protocols sequence for message with id ``cmdid``.
  result = -1
  for i in 0..<len(peer.caps):
    let proto = peer.caps[i]
    if cmdid >= proto.offset and cmdid < proto.offset + protoLength(proto.cap):
      result = i
      break

proc sendMessage*(peer: Peer, data: BytesRange): Future[bool] {.async.} =
  ## Sends RLP encoded message ``data`` to peer ``peer``. Returns ``true`` if
  ## message was successfully sent, and ``false`` otherwise.
  var header: RlpxHeader
  result = true
  if uint32(len(data)) <= MaxUInt24:
    # write the frame size in the first 3 bytes of the header
    let length = len(data)
    header[0] = byte((length shr 16) and 0xFF)
    header[1] = byte((length shr 8) and 0xFF)
    header[2] = byte(length and 0xFF)
    peer.sbuffer.setLen(encryptedLength(length))
    let res = encrypt(peer.secrets, header, data.toOpenArray, peer.sbuffer)
    if res != RlpxStatus.Success:
      debug "Failed to encrypt message", peer = $peer, error = $res,
                                         size = $len(data)
      result = false
  else:
    debug "RLPx message size exceeds limit", peer = $peer, size = $len(data)
    result = false

  if result:
    try:
      let cnt = await peer.transp.write(peer.sbuffer)
      if cnt != len(peer.sbuffer):
        result = false
    except:
      debug "Failed to send message", peer = $peer, size = $len(data)
      result = false

proc recvMessage*(peer: Peer): Future[EthereumMessage] {.async.} =
  ## Receive first incoming Ethereum frame message from networking stream of
  ## peer's `peer`.
  ## Returns message with id ``MsgBad``, if there problems with connection or
  ## decrypting of incoming message.
  var
    header: array[32, byte]
    success = true

  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)

  try:
    await peer.transp.readExactly(addr header[0], 32)
  except TransportIncompleteError:
    debug "Remote peer disconnected", peer = $peer
    peer.state = Disconnected
    success = false
  except TransportOsError:
    debug "Networking error", peer = $peer, msg = getCurrentExceptionMsg()
    peer.state = Disconnected
    success = false

  if not success: return

  var msgSize: int
  if decryptHeaderAndGetMsgSize(peer.secrets, header,
                                msgSize) != RlpxStatus.Success:
    return

  peer.rbuffer.setLen(encryptedLength(msgSize) - RlpHeaderLength - RlpMacLength)

  try:
    await peer.transp.readExactly(addr peer.rbuffer[0], len(peer.rbuffer))
  except TransportIncompleteError:
    debug "Remote peer disconnected", peer = $peer
    peer.state = Disconnected
    success = false
  except TransportOsError:
    debug "Networking error", peer = $peer, msg = getCurrentExceptionMsg()
    peer.state = Disconnected
    success = false

  if not success: return

  let decryptedMaxLength = decryptedLength(msgSize)
  var decryptedBytes = newSeq[byte](decryptedMaxLength)
  var decryptedLength = 0

  if decryptBody(peer.secrets, peer.rbuffer, msgSize,
                 decryptedBytes, decryptedLength) != RlpxStatus.Success:
    return

  decryptedBytes.setLen(decryptedLength)
  try:
    var data = rlpFromBytes(decryptedBytes.toRange())
    result.id = data.read(int)
    result.data = data
    peer.metrics.bytesCount += uint64(decryptedLength)
  except:
    debug "Could not decode RLP message", peer = $peer,
                                          msg = getCurrentExceptionMsg()
    result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)

  return

proc supports*(peer: Peer, cap: ECap): int =
  ## Returns index of capability in peer's list of synchronized capabilities.
  ## If capability is not supported ``-1`` will be returned.
  result = -1
  for i in 0..<len(peer.caps):
    if peer.caps[i].cap == cap:
      result = i
      break

proc supports*(peer: Peer, caps: openarray[ECap]): int =
  ## Returns index of most recent version capability in peer's list of
  ## synchronized.
  ## If there no capabilities present ``-1`` will be returned.
  result = -1
  for i in 0..<len(peer.caps):
    if peer.caps[i].cap in caps:
      if result == -1:
        result = i
      else:
        if uint(peer.caps[result].cap) < uint(peer.caps[i].cap):
          result = i

proc subscribe*(peer: Peer, epcap: EPeerCap, cmd: int,
                fut: Future[EthereumMessage]) =
  ## Subscribe future ``fut`` to specific command ``cmd`` of protocol ``epcap``.
  ## Future will be completed when specific message will be received.
  let msgId = epcap.cmdId(cmd)
  doAssert(msgId < len(peer.subscribers))
  peer.subscribers[msgId] = fut

proc unsubscribe*(peer: Peer, epcap: EPeerCap, cmd: int) =
  ## Unsubscribe future for specific command ``cmd`` of protocol ``epcap``.
  let msgId = epcap.cmdId(cmd)
  doAssert(msgId < len(peer.subscribers))
  peer.subscribers[msgId] = nil

proc close*(peer: Peer) =
  ## Close peer ``peer`` and free resources.
  if not peer.liveFuture.finished:
    peer.state = Disconnected
    peer.transp.close()
    peer.liveFuture.complete()

proc join*(peer: Peer): Future[void] =
  ## Returns future which will be completed when remote peer got disconnected.
  result = peer.liveFuture

proc pong(peer: Peer) {.async.} =
  var writer = initRlpWriter()
  writer.append(0x03)
  writer.startList(0)
  if not await peer.sendMessage(finish(writer)):
    peer.close()
  else:
    debug "Pong response has been sent", peer = $peer

proc notifyAll(peer: Peer, msg: EthereumMessage, urgent = false) =
  ## This is private procedures used to notify all waiting subscribers and
  ## interfaces of ``peer`` about particular message ``msg``. Mostly used to
  ## notify about received malformed/incorrect message or ``Disconnect``
  ## message.
  for i in 0..<len(peer.subscribers):
    if not isNil(peer.subscribers[i]) and not peer.subscribers[i].finished:
      peer.subscribers[i].complete(msg)
  for i in 0..<len(peer.queues):
    if not urgent:
      peer.queues[i].addLastNoWait(msg)
    else:
      peer.queues[i].addFirstNoWait(msg)

proc recvLoop(peer: Peer) {.async.} =
  ## Main receiving loop procedure, it processes all incoming messages from the
  ## ``peer`` and route it to subscribers and/or interfaces.
  var badMsg = EthereumMessage(id: -1, data: zeroBytesRlp)

  while true:
    var msg: EthereumMessage
    var msgData: Rlp
    if peer.state notin {None, Connected}:
      # Peer is not connected, notifying subscribers and protocols' intefaces
      peer.notifyAll(badMsg, true)
      break

    msg = await peer.recvMessage()
    if msg.id == MsgBad:
      # Received incorrect message, notifying subscribers and protocol's
      # interfaces
      peer.notifyAll(badMsg, true)
      break

    elif msg.id == MsgDisconnect:
      # Received `Disconnect` message, notifying subscribers and protocols
      # interfaces
      var malformed = false
      # Attempt to decode `Disconnect` message.
      if (not msg.data.isList()) or (msg.data.listLen() != 1):
        debug "Malformed disconnect message received", peer = $peer,
                                                     islist = msg.data.isList(),
                                                 listLength = msg.data.listLen()
        malformed = true
      try:
        msg.data.enterList()
        let reason = msg.data.read(int)
        debug "Disconnect message received", peer = $peer, reason = $reason,
                                             reasonMsg = $getReason(reason)
      except:
        debug "Malformed disconnect message received", peer = $peer,
                                            exception = getCurrentExceptionMsg()
        malformed = true

      if malformed:
        peer.notifyAll(badMsg, true)
      else:
        peer.notifyAll(msg)
      break

    elif msg.id == MsgPing:
      # Received `Ping` message.
      debug "Received ping request", peer = $peer
      asyncCheck peer.pong()

    elif msg.id == MsgPong:
      # Received `Pong` message.
      if not isNil(peer.subscribers[msg.id]) and
         not peer.subscribers[msg.id].finished:
        peer.subscribers[msg.id].complete(msg)
      else:
        # Unexpected `Pong` message received, possibly protocol breach.
        debug "Unexpected pong message received", peer = $peer
        peer.notifyAll(badMsg, true)
        break
    else:
      # Received subprotocol message.
      if not isNil(peer.subscribers[msg.id]) and
         not peer.subscribers[msg.id].finished:
        # If there subscriber for this message notify only subscriber.
        peer.subscribers[msg.id].complete(msg)
      else:
        # If there no subscribers for this message notify sub-protocol message
        # queue.
        let index = peer.toIndex(msg.id)
        if index == -1:
          peer.notifyAll(badMsg, true)
          break
        else:
          peer.queues[index].addLastNoWait(msg)

  if peer.state notin {Disconnected}:
    peer.close()

proc getMessage*(peer: Peer,
                 epcap: EPeerCap): Future[EthereumMessage] {.inline.} =
  ## Wait until you receive message from peer ``peer`` for sub-protocol
  ## ``epcap``.
  ## The returned message can be of the following types:
  ## - `MsgBad`, if remote peer sent malformed/incorrect message frame or
  ##   disconnected.
  ## - `MsgDisconnect` if remote peer sent disconnect message with reason.
  ## - Sub-protocol related message
  result = peer.queues[epcap.index].get()

proc ping*(peer: Peer): Future[int] {.async.} =
  ## Send ping message to remote peer ``peer`` and wait for pong message.
  ## Returns number of milliseconds spent, if returned integer is `-1` remote
  ## peer returned malformed message or disconnected.
  if peer.state == Connected:
    var writer = initRlpWriter()
    writer.append(MsgPing)
    writer.startList(0)
    var start = fastEpochTime()
    if not await peer.sendMessage(writer.finish()):
      result = -1
      peer.close()
    else:
      var fut = newFuture[EthereumMessage]("ping.answer")
      peer.subscribers[MsgPong] = fut
      var msg = await fut
      peer.subscribers[MsgPong] = nil
      if msg.id == MsgPong:
        result = int(fastEpochTime() - start)
      else:
        result = -1

proc disconnect*(peer: Peer, reason: DisconnectReason) {.async.} =
  ## Send disconnect message to remote peer ``peer`` with reason ``reason``.
  ## Please note, that this procedure will close connection and you don't need
  ## to call ``peer.close()``.
  if peer.state in {None, Connected}:
    var writer = initRlpWriter()
    writer.append(MsgDisconnect)
    writer.startList(1)
    writer.append(reason)
    peer.state = Disconnecting
    # We don't care about sending result, just because we disconnecting.
    let res = await peer.sendMessage(writer.finish())
    peer.close()

proc hello(en: EthereumNode, peer: Peer): Future[bool] {.async.} =
  ## Perform initial devP2P `hello` handshake.
  ## Returns ``true`` on successfull handshake, and ``false`` otherwise.
  var
    nodeId: NodeId
    rlpcaps: seq[RlpCap]

  result = true
  var writer = initRlpWriter()
  writer.append(MsgHello)
  writer.startList(5)
  writer.append(en.netver)
  writer.append(en.clientId)
  writer.append(en.caps.toRlp())
  writer.append(int(en.port))
  writer.append(en.keys.pubkey.getRaw())

  if await peer.sendMessage(writer.finish()):
    var msg = await peer.recvMessage()
    if msg.id == MsgHello:
      if (not msg.data.isList()) or (msg.data.listLen() != 5):
        debug "Malformed hello message received", peer = $peer,
                                                  islist = msg.data.isList(),
                                                 listLength = msg.data.listLen()
        return false

      try:
        msg.data.enterList()
        peer.version = msg.data.read(int)
        peer.clientid = msg.data.read(string)
        rlpcaps = msg.data.read(seq[RlpCap])
        let port = Port(msg.data.read(int) and 0xFFFF)
        let pubkeyRaw = msg.data.read(array[RawPublicKeySize, byte])
        nodeId = initPublicKey(pubkeyRaw).toNodeId()
      except:
        debug "Malformed hello message received", peer = $peer,
                                            exception = getCurrentExceptionMsg()
        result = false

      if not result:
        return

      if nodeId != peer.node.id:
        debug "Unexpected identity", peer = $peer, nodeId = $peer.node.id,
                                     helloId = $nodeId
        await peer.disconnect(UnexpectedIdentity)
        return false

      peer.allcaps = fromRlp(rlpcaps)
      peer.caps = sync(en.caps, peer.allcaps)
      if len(peer.caps) == 0:
        debug "There no compatible protocols with peer", peer = $peer,
                                                      peercaps = $peer.allcaps,
                                                      ourcaps = $en.caps
        await peer.disconnect(UselessPeer)
        return false

      ## Initializing sub-protocol message queues.
      peer.queues.setLen(len(peer.caps))
      for i in 0..<len(peer.queues):
        peer.queues[i] = newAsyncQueue[EthereumMessage]()

      return true

    elif msg.id == MsgDisconnect:
      if (not msg.data.isList()) or (msg.data.listLen() != 1):
        debug "Malformed disconnect message received", peer = $peer,
                                                     islist = msg.data.isList(),
                                                 listLength = msg.data.listLen()
        return false
      try:
        msg.data.enterList()
        let reason = msg.data.read(int)
        debug "Disconnect message received", peer = $peer, reason = $reason,
                                             reasonMsg = $getReason(reason)
      except:
        debug "Malformed disconnect message received", peer = $peer,
                                            exception = getCurrentExceptionMsg()
      return false
    else:
      debug "Unexpected message received while in handshake", peer = $peer,
                                                              msgId = $msg.id
      return false
  else:
    return false

proc authenticate(en: EthereumNode, peer: Peer,
                  flags: set[HandshakeFlag]): Future[bool] {.async.} =
  ## Perform initial cryptography authentication with remote peer ``peer``.
  ## Returns ``true`` on success and ``false`` on error.
  ##
  ## Use ``flags`` to specify your role as ``Initiator``, if you connecting to
  ## remote peer, or ``Responder`` if you accepting connection from remote peer.
  var secrets: ConnectionSecret
  var handshake = newHandshake(flags)
  handshake.host = en.keys
  result = false

  if Initiator in flags:
    # Outgoing connection
    var authMsg: array[AuthMessageMaxEIP8, byte]
    var authMsgLen = 0
    if authMessage(handshake, peer.node.node.pubkey, authMsg,
                   authMsgLen) != AuthStatus.Success:
      debug "Could not create authentication message", peer = $peer
      return

    try:
      let r0 = await peer.transp.write(addr authMsg[0], authMsgLen)
      checkIncomplete(r0, authMsgLen)

      debug "Authentication message has been sent", peer = $peer

      let initialSize = handshake.expectedLength
      peer.rbuffer.setLen(initialSize)

      await peer.transp.readExactly(addr peer.rbuffer[0], len(peer.rbuffer))
      var r1 = handshake.decodeAckMessage(peer.rbuffer)
      if r1 == AuthStatus.IncompleteError:
        peer.rbuffer.setLen(handshake.expectedLength)
        await peer.transp.readExactly(addr peer.rbuffer[initialSize],
                                      len(peer.rbuffer) - initialSize)
        r1 = handshake.decodeAckMessage(peer.rbuffer)
      if r1 != AuthStatus.Success:
        info "Authentication failed", peer = $peer, status = $r1
        return

      debug "Authentication ACK message received", peer = $peer
      result = true

      let r2 = handshake.getSecrets(authMsg.toOpenArray(0, authMsgLen - 1),
                                    peer.rbuffer, secrets)
      if r2 != AuthStatus.Success:
        info "Authentication failed", peer = $peer, status = $r2
        return
      result = true

    except TransportIncompleteError:
      debug "Remote peer disconnected while waiting ACK message", peer = $peer
    except PeerWriteIncomplete:
      debug "Remote peer disconnected while sending AUTH message", peer = $peer
    except TransportOsError:
      debug "Network error while authenticating", peer = $peer,
                                                  msg = getCurrentExceptionMsg()
    except:
      debug "Unexpected error while authenticating", peer = $peer,
                                                  msg = getCurrentExceptionMsg()

  elif Responder in flags:
    # Incoming connection
    try:
      let initialSize = handshake.expectedLength
      peer.rbuffer.setLen(initialSize)

      await peer.transp.readExactly(addr peer.rbuffer[0], len(peer.rbuffer))
      var r0 = handshake.decodeAuthMessage(peer.rbuffer)
      if r0 == AuthStatus.IncompleteError:
        peer.rbuffer.setLen(handshake.expectedLength)
        await peer.transp.readExactly(addr peer.rbuffer[initialSize],
                                      len(peer.rbuffer) - initialSize)
        r0 = handshake.decodeAuthMessage(peer.rbuffer)

      if r0 != AuthStatus.Success:
        info "Authentication failed", peer = $peer, status = $r0
        result = false
        return

      var ackMsg: array[AckMessageMaxEIP8, byte]
      var ackMsgLen: int
      if handshake.ackMessage(ackMsg, ackMsgLen) != AuthStatus.Success:
        debug "Could not create authentication ack message", peer = $peer
        result = false
        return

      let r1 = await peer.transp.write(addr ackMsg[0], ackMsgLen)
      checkIncomplete r1, ackMsgLen

      let r2 = handshake.getSecrets(peer.rbuffer,
                                    ackMsg.toOpenArray(0, ackMsgLen - 1),
                                    secrets)
      if r2 != AuthStatus.Success:
        info "Authentication failed", peer = $peer, status = $r2
        return

      # We can obtain remote public key only after authentication
      peer.node.node.pubkey = handshake.remoteHPubkey
      peer.node.id = handshake.remoteHPubkey.toNodeId()
      result = true

    except TransportIncompleteError:
      debug "Remote peer disconnected while waiting AUTH message", peer = $peer
    except PeerWriteIncomplete:
      debug "Remote peer disconnected while sending ACK message", peer = $peer
    except TransportOsError:
      debug "Network error while authenticating", peer = $peer,
                                                  msg = getCurrentExceptionMsg()
    except:
      debug "Unexpected error while authenticating", peer = $peer,
                                                  msg = getCurrentExceptionMsg()

  if result:
    initSecretState(secrets, peer.secrets)
    burnMem(secrets)

proc handshake(en: EthereumNode, peer: Peer): Future[bool] {.async.} =
  ## Perform initial handshake and sub-protocols handshake.
  ## Returns ``true`` on success and ``false`` on error

  # Perform devP2P `hello` handshake
  let r0 = await en.hello(peer)
  if not r0: return false

  debug "Peer capabilities", peer = $peer, supportedCaps = $peer.allcaps,
                             caps = $peer.caps

  # Interfaces instantiation
  peer.ifaces.setLen(len(peer.caps))
  for i in 0..<len(peer.caps):
    var iface: EInterface
    for proto in en.protocols:
      if peer.caps[i].cap == proto.cap:
        try:
          iface = proto.init(en, peer, peer.caps[i])
        except:
          debug "Subprotocol initialization error", peer = $peer,
                                                    protocol = $peer.caps[i],
                                                  msg = getCurrentExceptionMsg()
        break
    if isNil(iface):
      return false
    else:
      peer.ifaces[i] = iface

  # Starting receiving loop
  asyncCheck peer.recvLoop()

  # Sub-protocol interfaces handshake
  for i in 0..<len(peer.ifaces):
    var res: bool
    try:
      res = await peer.ifaces[i].handshake(peer)
    except:
      debug "Subprotocol handshake failed", peer = $peer,
                                            protocol = $peer.caps[i],
                                            msg = getCurrentExceptionMsg()
    if not res:
      return false

  peer.metrics.startTime = fastEpochTime()
  result = true

proc newEthereumNode*(networkId: int, seckey: PrivateKey,
                      clientId: string = "nim-eth-p2p",
                      port: Port = Port(30303),
                      netversion: int = 4): EthereumNode =
  ## Create new ``EthereumNode`` object.
  ## 
  ## ``networkId`` integer code of network where this EthereumNode supposed to
  ## run (1 - Main, 2 - Morden, 3 - Ropsten, 4 - Rinkeby, 42 - Kovan).
  ## 
  ## ``seckey`` EthereumNode private key, which is used to identify this node
  ## and to establish secure connections with other nodes.
  ## 
  ## ``clientId`` test string identifier of this client.
  ## 
  ## ``port`` local port to which this EthereumNode will be bound.
  ## 
  ## ``netversion`` devP2P protocol version. (4 - original protocol version,
  ## 5 - protocol with Snappy compression support).
  new result
  result.netver = netversion
  result.clientId = clientId
  result.port = port
  result.caps = newECapList()
  result.protocols = newSeq[EProtocol]()
  result.keys = KeyPair(seckey: seckey, pubkey: seckey.getPublicKey())
  result.network = networkId

proc registerProtocol*(en: EthereumNode, cap: ECap, ifp: EInterfaceProc) =
  ## Register protocol ``cap`` and interface ``ifp`` with Ethereum
  ## Node ``en``.
  doAssert(not isNil(ifp))
  en.caps.register(cap)
  en.protocols.add(EProtocol(cap: cap, init: ifp))

proc unregisterProcol*(en: EthereumNode, cap: ECap) =
  ## Unregister protocol ``cap`` and corresponding interface from Ethereum
  ## Node ``en``.
  en.caps.unregister(cap)
  var protocols = newSeq[EProtocol]()
  for item in en.protocols:
    if item.cap != cap:
      protocols.add(item)
  en.protocols = protocols

proc newPeer*(): Peer =
  ## Create new ``Peer`` object and allocate all needed structures.
  new result
  result.rbuffer = newSeqOfCap[byte](PeerRecvBufferInitialSize)
  result.sbuffer = newSeqOfCap[byte](PeerSendBufferInitialSize)
  result.queues = newSeq[AsyncQueue[EthereumMessage]]()
  result.ifaces = newSeq[EInterface]()
  result.liveFuture = newFuture[void]()
  result.responseTimeout = ResponseTimeout

proc connect*(en: EthereumNode, node: Node): Future[Peer] {.async.} =
  ## Establish connection to remote peer node ``node``.
  ## Perform authenticating and handshaking, returns new ``Peer`` object.
  ## Raises ``PeerException`` on error.
  result = newPeer()
  result.node = node
  let ta = initTAddress(node.node.address.ip, node.node.address.tcpPort)
  var success = true

  try:
    result.transp = await wait(connect(ta), ConnectTimeout)
  except AsyncTimeoutError:
    debug "Timeout exceeded while connecting", peer = $result
    success = false
  except:
    debug "Remote peer refused the network connection", peer = $result
    success = false

  if not success:
    raise newException(PeerException, "Unable to connect to node")

  debug "Connection to peer initiated", peer = $result

  try:
    let res = await wait(en.authenticate(result, {Initiator}),
                         AuthenticationTimeout)
    if not res:
      result.transp.close()
      success = false
  except AsyncTimeoutError:
    debug "Timeout exceeded while authenticating", peer = $result
    success = false
    result.transp.close()
  except:
    debug "Unexpected error", peer = $result,
                              exception = getCurrentExceptionMsg()
    success = false
    result.transp.close()

  if not success:
    raise newException(PeerException, "Unable to authenticate node")

  debug "Connection to peer authenticated", peer = $result

  try:
    let res = await wait(en.handshake(result), HandshakeTimeout)
    if not res:
      success = false
      result.transp.close()
    else:
      result.state = Connected
      result.flags = {Outgoing}

      # Start sub-protocol's message loops via `run` callback.
      for i in 0..<len(result.ifaces):
        result.ifaces[i].liveFuture = result.ifaces[i].run(result)

  except AsyncTimeoutError:
    debug "Timeout exceeded while in handshake", peer = $result
    success = false
    result.transp.close()
  except:
    debug "Unexpected error", peer = $result,
                              exception = getCurrentExceptionMsg()
    success = false
    result.transp.close()

  if not success:
    raise newException(PeerException, "Unable to establish handshake with node")

  debug "Handshake with peer completed", peer = $result
  info "Connection to peer established", peer = $result

proc connect*(en: EthereumNode, enode: ENode): Future[Peer] =
  ## Establish connection to remote peer ENode ``enode``.
  ## Perform authenticating and handshaking, returns new ``Peer`` object.
  ## Raises ``PeerException`` on error.
  result = connect(en, newNode(enode))

proc connect*(en: EthereumNode, uri: string): Future[Peer] =
  ## Establish connection to remote peer ENode address ``uri``.
  ## Perform authenticating and handshaking, returns new ``Peer`` object.
  ## Raises ``PeerException`` on error.
  var enode: ENode
  let res = initENode(uri, enode)
  if res != ENodeStatus.Success:
    result = newFuture[Peer]("peer.connect")
    result.fail(newException(PeerAddressException, ""))
  else:
    result = connect(en, enode)

proc accept*(en: EthereumNode,
             transp: StreamTransport): Future[Peer] {.async.} =
  ## Accept connection from remote peer which is connected to transport
  ## ``transp``.
  ## Perform authenticating and handshaking, returns new ``Peer`` object.
  ## Raises ``PeerException`` on error.
  result = newPeer()
  result.transp = transp
  let ta = transp.remoteAddress()
  var success = true

  result.node.node.address.ip = ta.address
  result.node.node.address.tcpPort = ta.port
  result.node.node.address.udpPort = ta.port

  debug "Connection to peer initiated", peer = $result

  try:
    let res = await wait(en.authenticate(result, {Responder}),
                         AuthenticationTimeout)
    if not res:
      success = false
      transp.close()
  except AsyncTimeoutError:
    debug "Timeout exceeded while authenticating", peer = $result
    success = false
    transp.close()
  except:
    debug "Unexpected error", peer = $result,
                              exception = getCurrentExceptionMsg()
    success = false

  if not success:
    raise newException(PeerException, "Unable to authenticate node")

  debug "Connection to peer authenticated", peer = $result

  try:
    let res = await wait(en.handshake(result), HandshakeTimeout)
    if not res:
      success = false
      transp.close()
    else:
      result.state = Connected
      result.flags = {Incoming}

      # Start sub-protocol's message loops via `run` callback.
      for i in 0..<len(result.ifaces):
        result.ifaces[i].liveFuture = result.ifaces[i].run(result)

  except AsyncTimeoutError:
    debug "Timeout exceeded while in handshake", peer = $result
    success = false
    transp.close()
  except:
    debug "Unexpected error", peer = $result,
                              exception = getCurrentExceptionMsg()
    success = false
    transp.close()

  if not success:
    raise newException(PeerException, "Unable to establish handshake with node")

  debug "Handshake with peer completed", peer = $result
  info "Connection to peer established", peer = $result
