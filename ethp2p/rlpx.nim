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
  macros, sets, algorithm, async, asyncnet, asyncfutures, net, logging,
  hashes, rlp, ranges/[stackarrays, ptr_arith], eth_keys,
  ethereum_types, kademlia, discovery, auth, rlpxcrypt, nimcrypto, enode

type
  ConnectionState = enum
    None,
    Connected,
    Disconnecting,
    Disconnected

  Peer* = ref object
    socket: AsyncSocket
    dispatcher: Dispatcher
    networkId: int
    secretsState: SecretState
    connectionState: ConnectionState
    protocolStates: seq[RootRef]
    remote*: Node

  MessageHandler* = proc(x: Peer, data: var Rlp)

  MessageInfo* = object
    id*: int
    name*: string
    thunk*: MessageHandler

  CapabilityName* = array[3, char]

  Capability* = object
    name*: CapabilityName
    version*: int

  ProtocolInfo* = ref object
    name*: CapabilityName
    version*: int
    messages*: seq[MessageInfo]
    index: int # the position of the protocol in the
                # ordered list of supported protocols

  Dispatcher = ref object
    # The dispatcher stores the mapping of negotiated message IDs between
    # two connected peers. The dispatcher objects are shared between
    # connections running with the same set of supported protocols.
    #
    # `protocolOffsets` will hold one slot of each locally supported
    # protocol. If the other peer also supports the protocol, the stored
    # offset indicates the numeric value of the first message of the protocol
    # (for this particular connection). If the other peer doesn't support the
    # particular protocol, the stored offset is -1.
    #
    # `thunks` holds a mapping from valid message IDs to their handler procs.
    #
    protocolOffsets: seq[int]
    thunks: seq[MessageHandler]

  UnsupportedProtocol* = object of Exception
    # This is raised when you attempt to send a message from a particular
    # protocol to a peer that doesn't support the protocol.

  MalformedMessageError* = object of Exception

const
  baseProtocolVersion = 4
  clienId = "Nimbus 0.1.0"

var
  gProtocols = newSeq[ProtocolInfo](0)
  gCapabilities = newSeq[Capability](0)
  gDispatchers = initSet[Dispatcher]()
  devp2p: ProtocolInfo

# Dispatcher
#

proc `$`*(p: Peer): string {.inline.} = $p.remote

proc hash(d: Dispatcher): int =
  hash(d.protocolOffsets)

proc `==`(lhs, rhs: Dispatcher): bool =
  lhs.protocolOffsets == rhs.protocolOffsets

template totalThunks(d: Dispatcher): int =
  d.thunks.len

template getThunk(d: Dispatcher, idx: int): MessageHandler =
  protocols.thunks[idx]

proc describeProtocols(d: Dispatcher): string =
  result = ""
  for i in 0 ..< gProtocols.len:
    if d.protocolOffsets[i] != -1:
      if result.len != 0: result.add(',')
      for c in gProtocols[i].name: result.add(c)

proc getDispatcher(otherPeerCapabilities: openarray[Capability]): Dispatcher =
  # XXX: sub-optimal solution until progress is made here:
  # https://github.com/nim-lang/Nim/issues/7457
  # We should be able to find an existing dispatcher without allocating a new one

  new(result)
  newSeq(result.protocolOffsets, gProtocols.len)

  var nextUserMsgId = 0x10 + 1

  for i in 0 .. <gProtocols.len:
    let localProtocol = gProtocols[i]

    block findMatchingProtocol:
      for remoteCapability in otherPeerCapabilities:
        if localProtocol.name == remoteCapability.name and
           localProtocol.version == remoteCapability.version:
          result.protocolOffsets[i] = nextUserMsgId
          nextUserMsgId += localProtocol.messages.len
          break findMatchingProtocol
      # the local protocol is not supported by the other peer
      # indicate this by a -1 offset:
      result.protocolOffsets[i] = -1

  if result in gDispatchers:
    return gDispatchers[result]
  else:
    template copyTo(src, dest; index: int) =
      for i in 0 ..< src.len:
        dest[index + i] = src[i].thunk

    result.thunks = newSeq[MessageHandler](nextUserMsgId)
    devp2p.messages.copyTo(result.thunks, 0)

    for i in 0 .. <gProtocols.len:
      if result.protocolOffsets[i] != -1:
        gProtocols[i].messages.copyTo(result.thunks, result.protocolOffsets[i])

    gDispatchers.incl result

# Protocol info objects
#

proc newProtocol(name: string, version: int): ProtocolInfo =
  new result
  result.name[0] = name[0]
  result.name[1] = name[1]
  result.name[2] = name[2]
  result.version = version
  result.messages = @[]

proc nameStr*(p: ProtocolInfo): string =
  result = newStringOfCap(3)
  for c in p.name: result.add(c)

proc cmp*(lhs, rhs: ProtocolInfo): int {.inline.} =
  for i in 0..2:
    if lhs.name[i] != rhs.name[i]:
      return int16(lhs.name[i]) - int16(rhs.name[i])
  return 0

proc registerMsg(protocol: var ProtocolInfo,
                 id: int, name: string, thunk: MessageHandler) =
  protocol.messages.add MessageInfo(id: id, name: name, thunk: thunk)

proc registerProtocol(protocol: ProtocolInfo) =
  # XXX: This can be done at compile-time in the future
  if protocol.version > 0:
    let pos = lowerBound(gProtocols, protocol)
    gProtocols.insert(protocol, pos)
    gCapabilities.insert(Capability(name: protocol.name, version: protocol.version), pos)
    for i in 0 ..< gProtocols.len:
      gProtocols[i].index = i
  else:
    devp2p = protocol

# RLP serialization
#

proc append*(rlpWriter: var RlpWriter, hash: KeccakHash) =
  rlpWriter.append(hash.data)

proc read*(rlp: var Rlp, T: typedesc[KeccakHash]): T =
  result.data = rlp.read(type(result.data))

# Message composition and encryption
#

proc writeMsgId(p: ProtocolInfo, msgId: int, peer: Peer, rlpOut: var RlpWriter) =
  let baseMsgId = peer.dispatcher.protocolOffsets[p.index]
  if baseMsgId == -1:
    raise newException(UnsupportedProtocol,
                       p.nameStr & " is not supported by peer " & $peer.remote.id)
  rlpOut.append(baseMsgId + msgId)

proc dispatchMsg(peer: Peer, msgId: int, msgData: var Rlp) =
  template invalidIdError: untyped =
    raise newException(ValueError,
      "RLPx message with an invalid id " & $msgId &
      " on a connection supporting " & peer.dispatcher.describeProtocols)

  if msgId >= peer.dispatcher.thunks.len: invalidIdError()
  let thunk = peer.dispatcher.thunks[msgId]
  if thunk == nil: invalidIdError()

  thunk(peer, msgData)

proc send(p: Peer, data: BytesRange) {.async.} =
  # var rlp = rlpFromBytes(data)
  # echo "sending: ", rlp.read(int)
  # echo "payload: ", rlp.inspect
  var cipherText = encryptMsg(data, p.secretsState)
  await p.socket.send(addr cipherText[0], cipherText.len)

proc fullRecvInto(s: AsyncSocket, buffer: pointer, bufferLen: int) {.async.} =
  # XXX: This should be a library function
  var receivedBytes = 0
  while receivedBytes < bufferLen:
    let sz = await s.recvInto(buffer.shift(receivedBytes),
                              bufferLen - receivedBytes)
    if sz == 0:
      raise newException(IOError, "Socket disconnected")
    receivedBytes += sz

template fullRecvInto(s: AsyncSocket, buff: var openarray[byte]): auto =
  fullRecvInto(s, addr buff[0], buff.len)

proc recvMsg*(peer: Peer): Future[tuple[msgId: int, msgData: Rlp]] {.async.} =
  ##  This procs awaits the next complete RLPx message in the TCP stream

  var headerBytes: array[32, byte]
  await peer.socket.fullRecvInto(headerBytes)

  var msgSize: int
  if decryptHeaderAndGetMsgSize(peer.secretsState,
                                headerBytes, msgSize) != RlpxStatus.Success:
    return (-1, zeroBytesRlp)

  let remainingBytes = encryptedLength(msgSize) - 32
  # XXX: Migrate this to a thread-local seq
  var encryptedBytes = newSeq[byte](remainingBytes)
  await peer.socket.fullRecvInto(encryptedBytes.baseAddr, remainingBytes)

  let decryptedMaxLength = decryptedLength(msgSize)
  var
    decryptedBytes = newSeq[byte](decryptedMaxLength)
    decryptedBytesCount = 0

  if decryptBody(peer.secretsState, encryptedBytes, msgSize,
                 decryptedBytes, decryptedBytesCount) != RlpxStatus.Success:
    return (-1, zeroBytesRlp)

  decryptedBytes.setLen(decryptedBytesCount)
  var rlp = rlpFromBytes(decryptedBytes.toRange)
  let msgId = rlp.read(int)
  return (msgId, rlp)

proc nextMsg*(peer: Peer, MsgType: typedesc,
              discardOthers = false): Future[MsgType] {.async.} =
  ## This procs awaits a specific RLPx message.
  ## By default, other messages will be automatically dispatched
  ## to their responsive handlers unless `discardOthers` is set to
  ## true. This may be useful when the protocol requires a very
  ## specific response to a given request. Use with caution.
  const wantedId = MsgType.msgId

  while true:
    var (nextMsgId, nextMsgData) = await peer.recvMsg()
    if nextMsgId == wantedId:
      return nextMsgData.read(MsgType)
    elif not discardOthers:
      peer.dispatchMsg(nextMsgId, nextMsgData)

iterator typedParams(n: NimNode, skip = 0): (NimNode, NimNode) =
  for i in (1 + skip) ..< n.params.len:
    let paramNodes = n.params[i]
    let paramType = paramNodes[^2]

    for j in 0 .. < (paramNodes.len-2):
      yield (paramNodes[j], paramType)

proc chooseFieldType(n: NimNode): NimNode =
  ## Examines the parameter types used in the message signature
  ## and selects the corresponding field type for use in the
  ## message object type (i.e. `p2p.hello`).
  ##
  ## For now, only openarray types are remapped to sequences.
  result = n
  if n.kind == nnkBracketExpr and
     n[0].kind == nnkIdent and
     $n[0].ident == "openarray":
    result = n.copyNimTree
    result[0] = newIdentNode("seq")

proc getState(peer: Peer, proto: ProtocolInfo): RootRef =
  peer.protocolStates[proto.index]

template state*(connection: Peer, Protocol: typedesc): untyped =
  ## Returns the state object of a particular protocol for a
  ## particular connection.
  cast[ref Protocol.State](connection.getState(Protocol.info))

macro rlpxProtocol*(protoIdentifier: untyped,
                    version: static[int],
                    body: untyped): untyped =
  ## The macro used to defined RLPx sub-protocols. See README.
  var
    protoName = $protoIdentifier
    protoNameIdent = newIdentNode(protoName)
    nextId = BiggestInt 0
    protocol = genSym(nskVar, protoName & "Proto")
    newProtocol = bindSym "newProtocol"
    rlpFromBytes = bindSym "rlpFromBytes"
    read = bindSym "read"
    initRlpWriter = bindSym "initRlpWriter"
    finish = bindSym "finish"
    append = bindSym "append"
    send = bindSym "send"
    Peer = bindSym "Peer"
    writeMsgId = bindSym "writeMsgId"
    isSubprotocol = version > 0
    stateType: NimNode = nil

  # By convention, all Ethereum protocol names must be abbreviated to 3 letters
  assert protoName.len == 3

  result = newNimNode(nnkStmtList)
  result.add quote do:
    # One global variable per protocol holds the protocol run-time data
    var `protocol` = `newProtocol`(`protoName`, `version`)

    # Create a type actining as a pseudo-object representing the protocol (e.g. p2p)
    type `protoNameIdent`* = object

    # The protocol run-time data is available as a pseudo-field (e.g. `p2p.info`)
    template info*(P: type `protoNameIdent`): ProtocolInfo = `protocol`

  for n in body:
    case n.kind
    of {nnkCall, nnkCommand}:
      if n.len == 2 and n[0].kind == nnkIdent and $n[0].ident == "nextID":
        if n[1].kind == nnkIntLit:
          nextId = n[1].intVal
        else:
          error("nextID expects a single int value", n)
      else:
        error(repr(n) & " is not a recognized call in RLPx protocol definitions", n)
    of nnkTypeSection:
      if n.len == 1 and n[0][0].kind == nnkIdent and $n[0][0].ident == "State":
        stateType = genSym(nskType, protoName & "State")
        n[0][0] = stateType
        result.add n
        # Create a pseudo-field for the protocol State type (e.g. `p2p.State`)
        result.add quote do:
          template State*(P: type `protoNameIdent`): typedesc = `stateType`
      else:
        error("The only type that can be defined inside a RLPx protocol is the protocol's State type.")

    of nnkProcDef:
      let
        msgIdent = n.name.ident
        msgName = $msgIdent

      var
        thunkName = newNilLit()
        rlpWriter = genSym(nskVar, "writer")
        appendParams = newNimNode(nnkStmtList)
        peer = genSym(nskParam, "peer")

      if n.body.kind != nnkEmpty:
        # implement the receiving thunk proc that deserialzed the
        # message parameters and calls the user proc:
        var
          nCopy = n.copyNimTree
          rlp = genSym(nskParam, "rlp")
          connection = genSym(nskParam, "connection")

        nCopy.name = genSym(nskProc, msgName)
        var callUserProc = newCall(nCopy.name, connection)

        var readParams = newNimNode(nnkStmtList)

        for i in 2 ..< n.params.len: # we skip the return type and the
                                     # first param of type Peer
          let paramNodes = n.params[i]
          let paramType = paramNodes[^2]

          for j in 0 ..< (paramNodes.len-2):
            var deserializedParam = genSym(nskLet)

            readParams.add quote do:
              let `deserializedParam` = `read`(`rlp`, `paramType`)

            callUserProc.add deserializedParam

        thunkName = newIdentNode(msgName & "_thunk")
        var thunk = quote do:
          proc `thunkName`(`connection`: `Peer`, `rlp`: var Rlp) =
            `readParams`
            `callUserProc`

        if stateType != nil:
          # Define a local accessor for the current protocol state
          # inside each handler (e.g. peer.state.foo = bar)
          var localStateAccessor = quote:
            template state(connection: `Peer`): ref `stateType` =
              cast[ref `stateType`](connection.getState(`protocol`))

          nCopy.body.insert 0, localStateAccessor

        result.add nCopy, thunk

      var
        msgType = genSym(nskType, msgName & "Obj")
        msgTypeFields = newTree(nnkRecList)
        msgTypeBody = newTree(nnkObjectTy,
          newEmptyNode(),
          newEmptyNode(),
          msgTypeFields)

      var paramCount = 0
      # implement sending proc
      for param, paramType in n.typedParams(skip = 1):
        inc paramCount
        appendParams.add quote do:
          `append`(`rlpWriter`, `param`)

        msgTypeFields.add newTree(nnkIdentDefs,
          param, chooseFieldType(paramType), newEmptyNode())

      result.add quote do:
        # This is a type featuring a single field for each message param:
        type `msgType`* = `msgTypeBody`

        # Add a helper template for accessing the message type:
        # e.g. p2p.hello:
        template `msgIdent`*(T: type `protoNameIdent`): typedesc = `msgType`

        # Add a helper template for obtaining the message Id for
        # a particular message type:
        template msgId*(T: type `msgType`): int = `nextId`

      # XXX TODO: check that the first param has the correct type
      n.params[1][0] = peer
      echo n.params.treeRepr
      n.params[0] = newTree(nnkBracketExpr,
                            newIdentNode("Future"), newIdentNode("void"))

      let writeMsgId = if isSubprotocol:
        quote: `writeMsgId`(`protocol`, `nextId`, `peer`, `rlpWriter`)
      else:
        quote: `append`(`rlpWriter`, `nextId`)

      let paramCountNode = newLit(paramCount)
      n.body = quote do:
        var `rlpWriter` = `initRlpWriter`()
        `writeMsgId`
        `rlpWriter`.startList(`paramCountNode`)
        `appendParams`
        return `send`(`peer`, `finish`(`rlpWriter`))

      result.add n
      result.add newCall(bindSym("registerMsg"),
                         protocol,
                         newIntLitNode(nextId),
                         newStrLitNode($n.name),
                         thunkName)

      inc nextId
    else:
      error("illegal syntax in a RLPx protocol definition", n)

  result.add newCall(bindSym("registerProtocol"), protocol)
  when isMainModule: echo repr(result)

type
  DisconnectionReason* = enum
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
    SubprotocolReason = 0x10

rlpxProtocol p2p, 0:
  proc hello(peer: Peer,
             version: uint,
             clientId: string,
             capabilities: openarray[Capability],
             listenPort: uint,
             nodeId: array[RawPublicKeySize, byte]) =
    # peer.id = nodeId
    peer.dispatcher = getDispatcher(capabilities)

  proc disconnect(peer: Peer, reason: DisconnectionReason)

  proc ping(peer: Peer)

  proc pong(peer: Peer) =
    discard

template `^`(arr): auto =
  # passes a stack array with a matching `arrLen`
  # variable as an open array
  arr.toOpenArray(0, `arr Len` - 1)

proc validatePubKeyInHello(msg: p2p.hello, pubKey: PublicKey): bool =
  var pk: PublicKey
  recoverPublicKey(msg.nodeId, pk) == EthKeysStatus.Success and pk == pubKey

proc check(status: AuthStatus) =
  if status != AuthStatus.Success:
    raise newException(Exception, "Error: " & $status)

proc connectionEstablished(p: Peer, h: p2p.hello) =
  p.dispatcher = getDispatcher(h.capabilities)
  # p.id = h.nodeId
  p.connectionState = Connected
  newSeq(p.protocolStates, gProtocols.len)
  # XXX: initialize the sub-protocol states

proc initSecretState(hs: var Handshake, authMsg, ackMsg: openarray[byte], p: Peer) =
  var secrets: ConnectionSecret
  check hs.getSecrets(authMsg, ackMsg, secrets)
  initSecretState(secrets, p.secretsState)
  burnMem(secrets)

proc rlpxConnect*(myKeys: KeyPair, listenPort: Port, remote: Node): Future[Peer] {.async.} =
  # TODO: Make sure to close the socket in case of exception
  new result
  result.socket = newAsyncSocket()
  result.remote = remote
  await result.socket.connect($remote.node.address.ip, remote.node.address.tcpPort)

  var handshake = newHandshake({Initiator})
  handshake.host = myKeys

  var authMsg: array[AuthMessageMaxEIP8, byte]
  var authMsgLen = 0
  check authMessage(handshake, remote.node.pubkey, authMsg, authMsgLen)
  await result.socket.send(addr authMsg[0], authMsgLen)

  let initialSize = handshake.expectedLength
  var ackMsg = newSeq[byte](initialSize)
  await result.socket.fullRecvInto(ackMsg)
  var ret = handshake.decodeAckMessage(ackMsg)
  if ret == AuthStatus.IncompleteError:
    ackMsg.setLen(handshake.expectedLength)
    await result.socket.fullRecvInto(addr ackMsg[initialSize],
                                     len(ackMsg) - initialSize)
    ret = handshake.decodeAckMessage(ackMsg)
  check ret

  initSecretState(handshake, ^authMsg, ackMsg, result)

  if handshake.remoteHPubkey != remote.node.pubKey:
    raise newException(Exception, "Remote pubkey is wrong")

  discard result.hello(baseProtocolVersion, clienId,
                     gCapabilities, uint(listenPort), myKeys.pubkey.getRaw())

  var response = await result.nextMsg(p2p.hello, discardOthers = true)

  if not validatePubKeyInHello(response, remote.node.pubKey):
    warn "Remote nodeId is not its public key" # XXX: Do we care?

  connectionEstablished(result, response)

proc rlpxConnectIncoming*(myKeys: KeyPair, listenPort: Port, address: IpAddress, s: AsyncSocket): Future[Peer] {.async.} =
  new result
  result.socket = s
  var handshake = newHandshake({Responder})
  handshake.host = myKeys

  let initialSize = handshake.expectedLength
  var authMsg = newSeq[byte](initialSize)
  await s.fullRecvInto(authMsg)
  var ret = handshake.decodeAuthMessage(authMsg)
  if ret == AuthStatus.IncompleteError: # Eip8 auth message is likely
    authMsg.setLen(handshake.expectedLength)
    await s.fullRecvInto(addr authMsg[initialSize], len(authMsg) - initialSize)
    ret = handshake.decodeAuthMessage(authMsg)
  check ret

  var ackMsg: array[AckMessageMaxEIP8, byte]
  var ackMsgLen: int
  check handshake.ackMessage(ackMsg, ackMsgLen)
  await s.send(addr ackMsg[0], ackMsgLen)

  initSecretState(handshake, authMsg, ^ackMsg, result)

  var response = await result.nextMsg(p2p.hello, discardOthers = true)
  discard result.hello(baseProtocolVersion, clienId,
                     gCapabilities, listenPort.uint, myKeys.pubkey.getRaw())

  if validatePubKeyInHello(response, handshake.remoteHPubkey):
    warn "Remote nodeId is not its public key" # XXX: Do we care?

  let port = Port(response.listenPort)
  let address = Address(ip: address, tcpPort: port, udpPort: port)
  result.remote = newNode(initEnode(handshake.remoteHPubkey, address))

  connectionEstablished(result, response)

when isMainModule:
  import rlp

  rlpxProtocol aaa, 1:
    type State = object
      peerName: string

    proc hi(p: Peer, name: string) =
      p.state.peerName = name

  rlpxProtocol bbb, 1:
    type State = object
      messages: int

    proc foo(p: Peer, s: string, a, z: int) =
      p.state.messages += 1
      echo p.state(aaa).peerName

    proc bar(p: Peer, i: int, s: string)

  var p = Peer()
  discard p.bar(10, "test")

