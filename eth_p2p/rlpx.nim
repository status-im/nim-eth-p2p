#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import macros, sets, algorithm, logging, hashes
import rlp, ranges/[stackarrays, ptr_arith], eth_keys, ethereum_types,
       nimcrypto, asyncdispatch2
import kademlia, discovery, auth, rlpxcrypt, enode

type
  ConnectionState = enum
    None,
    Connected,
    Disconnecting,
    Disconnected

  Network* = ref object
    id: int
    protocolStates: seq[RootRef]

  Peer* = ref object
    transp: StreamTransport
    dispatcher: Dispatcher
    networkId: int
    nextRequestId: int
    network: Network
    secretsState: SecretState
    connectionState: ConnectionState
    protocolStates: seq[RootRef]
    remote*: Node

  MessageHandler* = proc(x: Peer, data: Rlp): Future[void]

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

  RlpxMessageKind = enum
    rlpxNotification,
    rlpxRequest,
    rlpxResponse

  UnsupportedProtocol* = object of Exception
    # This is raised when you attempt to send a message from a particular
    # protocol to a peer that doesn't support the protocol.

  MalformedMessageError* = object of Exception

const
  baseProtocolVersion = 4

var
  gProtocols: seq[ProtocolInfo]
  gCapabilities: seq[Capability]
  gDispatchers = initSet[Dispatcher]()
  devp2p: ProtocolInfo

# The variables above are immutable RTTI information. We need to tell
# Nim to not consider them GcSafe violations:
template rlpxProtocols: auto = {.gcsafe.}: gProtocols
template rlpxCapabilities: auto = {.gcsafe.}: gCapabilities
template devp2pProtocolInfo: auto = {.gcsafe.}: devp2p

# Dispatcher
#

proc `$`*(p: Peer): string {.inline.} = $p.remote

proc hash(d: Dispatcher): int =
  hash(d.protocolOffsets)

proc `==`(lhs, rhs: Dispatcher): bool =
  lhs.protocolOffsets == rhs.protocolOffsets

proc describeProtocols(d: Dispatcher): string =
  result = ""
  for i in 0 ..< rlpxProtocols.len:
    if d.protocolOffsets[i] != -1:
      if result.len != 0: result.add(',')
      for c in rlpxProtocols[i].name: result.add(c)

proc getDispatcher(otherPeerCapabilities: openarray[Capability]): Dispatcher =
  # XXX: sub-optimal solution until progress is made here:
  # https://github.com/nim-lang/Nim/issues/7457
  # We should be able to find an existing dispatcher without allocating a new one

  new(result)
  newSeq(result.protocolOffsets, rlpxProtocols.len)

  var nextUserMsgId = 0x10

  for i in 0 ..< rlpxProtocols.len:
    let localProtocol = rlpxProtocols[i]

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
    devp2pProtocolInfo.messages.copyTo(result.thunks, 0)

    for i in 0 ..< rlpxProtocols.len:
      if result.protocolOffsets[i] != -1:
        rlpxProtocols[i].messages.copyTo(result.thunks, result.protocolOffsets[i])

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
    if gProtocols.isNil: gProtocols = @[]
    if gCapabilities.isNil: gCapabilities = @[]
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

proc writeMsgId(p: ProtocolInfo, msgId: int, peer: Peer,
                rlpOut: var RlpWriter) =
  let baseMsgId = peer.dispatcher.protocolOffsets[p.index]
  doAssert baseMsgId != -1
  rlpOut.append(baseMsgId + msgId)

proc dispatchMsg(peer: Peer, msgId: int, msgData: var Rlp): Future[void] =
  template invalidIdError: untyped =
    raise newException(ValueError,
      "RLPx message with an invalid id " & $msgId &
      " on a connection supporting " & peer.dispatcher.describeProtocols)

  if msgId >= peer.dispatcher.thunks.len: invalidIdError()
  let thunk = peer.dispatcher.thunks[msgId]
  if thunk == nil: invalidIdError()

  return thunk(peer, msgData)

proc sendMsg(p: Peer, data: BytesRange): Future[int] =
  # var rlp = rlpFromBytes(data)
  # echo "sending: ", rlp.read(int)
  # echo "payload: ", rlp.inspect
  var cipherText = encryptMsg(data, p.secretsState)
  return p.transp.write(cipherText)

proc sendRequest(p: Peer, data: BytesRange, ResponseType: type): Future[ResponseType] =
  discard

proc recvMsg*(peer: Peer): Future[tuple[msgId: int, msgData: Rlp]] {.async.} =
  ##  This procs awaits the next complete RLPx message in the TCP stream

  var headerBytes: array[32, byte]
  await peer.transp.readExactly(addr headerBytes[0], 32)

  var msgSize: int
  if decryptHeaderAndGetMsgSize(peer.secretsState,
                                headerBytes, msgSize) != RlpxStatus.Success:
    return (-1, zeroBytesRlp)

  let remainingBytes = encryptedLength(msgSize) - 32
  # TODO: Migrate this to a thread-local seq
  # JACEK:
  #  or pass it in, allowing the caller to choose - they'll likely be in a
  #  better position to decide if buffer should be reused or not. this will
  #  also be useuful for chunked messages where part of the buffer may have
  #  been processed and needs filling in
  var encryptedBytes = newSeq[byte](remainingBytes)
  await peer.transp.readExactly(addr encryptedBytes[0], len(encryptedBytes))

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

proc waitSingleMsg(peer: Peer, MsgType: typedesc): Future[MsgType] {.async.} =
  const wantedId = MsgType.msgId
  while true:
    var (nextMsgId, nextMsgData) = await peer.recvMsg()
    if nextMsgId == wantedId:
      return nextMsgData.read(MsgType)

proc nextMsg*(peer: Peer, MsgType: typedesc): Future[MsgType] {.async.} =
  ## This procs awaits a specific RLPx message.
  ## Any messages received while waiting will be dispatched to their
  ## respective handlers. The designated message handler will also run
  ## to completion before the future returned by `nextMsg` is resolved.
  const wantedId = MsgType.msgId

  while true:
    var (nextMsgId, nextMsgData) = await peer.recvMsg()
    # echo "got msg(", nextMsgId, "): ", nextMsgData.inspect
    if nextMsgData.listLen != 0:
      nextMsgData = nextMsgData.listElem(0)
    await peer.dispatchMsg(nextMsgId, nextMsgData)
    if nextMsgId == wantedId:
      return nextMsgData.read(MsgType)

proc registerRequest(peer: Peer, responseFuture: FutureBase): uint =
  discard

proc resolveResponseFuture(peer: Peer, msgId: int, msg: pointer, reqID: uint) =
  discard

iterator typedParams(n: NimNode, skip = 0): (NimNode, NimNode) =
  for i in (1 + skip) ..< n.params.len:
    let paramNodes = n.params[i]
    let paramType = paramNodes[^2]

    for j in 0 ..< paramNodes.len - 2:
      yield (paramNodes[j], paramType)

proc chooseFieldType(n: NimNode): NimNode =
  ## Examines the parameter types used in the message signature
  ## and selects the corresponding field type for use in the
  ## message object type (i.e. `p2p.hello`).
  ##
  ## For now, only openarray types are remapped to sequences.
  result = n
  if n.kind == nnkBracketExpr and eqIdent(n[0], "openarray"):
    result = n.copyNimTree
    result[0] = newIdentNode("seq")

proc getState(peer: Peer, proto: ProtocolInfo): RootRef =
  peer.protocolStates[proto.index]

template state*(connection: Peer, Protocol: typedesc): untyped =
  ## Returns the state object of a particular protocol for a
  ## particular connection.
  cast[ref Protocol.State](connection.getState(Protocol.protocolInfo))

proc getNetworkState(peer: Peer, proto: ProtocolInfo): RootRef =
  peer.network.protocolStates[proto.index]

template networkState*(connection: Peer, Protocol: typedesc): untyped =
  ## Returns the network state object of a particular protocol for a
  ## particular connection.
  cast[ref Protocol.NetworkState](connection.getNetworkState(Protocol.protocolInfo))

macro rlpxProtocol*(protoIdentifier: untyped,
                    version: static[int],
                    body: untyped): untyped =
  ## The macro used to defined RLPx sub-protocols. See README.
  var
    protoName = $protoIdentifier
    protoNameIdent = newIdentNode(protoName)
    resultIdent = newIdentNode "result"
    protocol = genSym(nskVar, protoName & "Proto")
    newProtocol = bindSym "newProtocol"
    rlpFromBytes = bindSym "rlpFromBytes"
    read = bindSym "read"
    initRlpWriter = bindSym "initRlpWriter"
    startList = bindSym "startList"
    finish = bindSym "finish"
    append = bindSym "append"
    sendMsg = bindSym "sendMsg"
    sendRequest = bindSym "sendRequest"
    Peer = bindSym "Peer"
    writeMsgId = bindSym "writeMsgId"
    resolveResponseFuture = bindSym "resolveResponseFuture"
    registerRequest = bindSym "registerRequest"
    isSubprotocol = version > 0
    msgThunksAndRegistrations = newNimNode(nnkStmtList)
    nextId = 0
    finalOutput = newNimNode(nnkStmtList)
    stateType: NimNode = nil
    networkStateType: NimNode = nil
    useRequestIds = true

  # By convention, all Ethereum protocol names must be abbreviated to 3 letters
  assert protoName.len == 3

  proc addMsgHandler(msgId: int, n: NimNode,
                     msgKind = rlpxNotification,
                     responseMsgId = -1,
                     responseRecord: NimNode = nil): NimNode =
    let
      msgIdent = n.name
      msgName = $n.name

    var
      paramCount = 0

      # variables used in the sending procs
      msgRecipient = genSym(nskParam, "msgRecipient")
      rlpWriter = genSym(nskVar, "writer")
      appendParams = newNimNode(nnkStmtList)

      # variables used in the receiving procs
      msgSender = genSym(nskParam, "msgSender")
      receivedRlp = genSym(nskVar, "rlp")
      receivedMsg = genSym(nskVar, "msg")
      readParams = newNimNode(nnkStmtList)
      callResolvedResponseFuture = newNimNode(nnkStmtList)

      # nodes to store the user-supplied message handling proc if present
      userHandlerProc: NimNode = nil
      userHandlerCall: NimNode = nil
      awaitUserHandler = newStmtList()

      # a record type associated with the message
      msgRecord = genSym(nskType, msgName & "Obj")
      msgRecordFields = newTree(nnkRecList)
      msgRecordBody = newTree(nnkObjectTy,
        newEmptyNode(),
        newEmptyNode(),
        msgRecordFields)

    result = msgRecord

    case msgKind
    of rlpxNotification: discard
    of rlpxRequest:
      # Each request is registered so we can resolve it when the response
      # arrives. There are two types of protocols: LES-like protocols use
      # explicit `reqID` sent over the wire, while the ETH wire protocol
      # assumes there is one outstanding request at a time (if there are
      # multiple requests we'll resolve them in FIFO order).
      if useRequestIds:
        inc paramCount
        appendParams.add quote do:
          `append`(`rlpWriter`, `registerRequest`(`msgRecipient`,
                                                  `resultIdent`,
                                                  `responseMsgId`))
      else:
        appendParams.add quote do:
          discard `registerRequest`(`msgRecipient`,
                                    `resultIdent`,
                                    `responseMsgId`)
    of rlpxResponse:
      if useRequestIds:
        var reqId = genSym(nskLet, "reqId")

        # Messages using request Ids
        readParams.add quote do:
          let `reqId` = `read`(`receivedRlp`, uint)

        callResolvedResponseFuture.add quote do:
          `resolveResponseFuture`(`msgSender`, `msgId`, addr(`receivedMsg`), `reqId`)
      else:
        callResolvedResponseFuture.add quote do:
          `resolveResponseFuture`(`msgSender`, `msgId`, addr(`receivedMsg`), -1)

    if n.body.kind != nnkEmpty:
      # implement the receiving thunk proc that deserialzed the
      # message parameters and calls the user proc:
      userHandlerProc = n.copyNimTree
      userHandlerProc.name = genSym(nskProc, msgName)
      userHandlerProc.addPragma newIdentNode"async"

      # This is the call to the user supplied handled. Here we add only the
      # initial peer param, while the rest of the params will be added later.
      userHandlerCall = newCall(userHandlerProc.name, msgSender)

      # When there is a user handler, it must be awaited in the thunk proc.
      # Above, by default `awaitUserHandler` is set to a no-op statement list.
      awaitUserHandler = newCall("await", userHandlerCall)

      msgThunksAndRegistrations.add(userHandlerProc)

      # Define local accessors for the peer and the network protocol states
      # inside each user message handler proc (e.g. peer.state.foo = bar)
      if stateType != nil:
        var localStateAccessor = quote:
          template state(p: `Peer`): ref `stateType` =
            cast[ref `stateType`](p.getState(`protocol`))

        userHandlerProc.body.insert 0, localStateAccessor

      if networkStateType != nil:
        var networkStateAccessor = quote:
          template networkState(p: `Peer`): ref `networkStateType` =
            cast[ref `networkStateType`](p.getNetworkState(`protocol`))

        userHandlerProc.body.insert 0, networkStateAccessor

    for param, paramType in n.typedParams(skip = 1):
      inc paramCount

      # This is a fragment of the sending proc that
      # serializes each of the passed parameters:
      appendParams.add quote do:
        `append`(`rlpWriter`, `param`)

      # Each message has a corresponding record type.
      # Here, we create its fields one by one:
      msgRecordFields.add newTree(nnkIdentDefs,
        param, chooseFieldType(paramType), newEmptyNode())

      # The received RLP data is deserialized to a local variable of
      # the message-specific type. This is done field by field here:
      readParams.add quote do:
        `receivedMsg`.`param` = `read`(`receivedRlp`, `paramType`)

      # If there is user message handler, we'll place a call to it by
      # unpacking the fields of the received message:
      if userHandlerCall != nil:
        userHandlerCall.add newDotExpr(receivedMsg, param)

    let thunkName = newIdentNode(msgName & "_thunk")

    msgThunksAndRegistrations.add quote do:
      proc `thunkName`(`msgSender`: `Peer`, data: Rlp) {.async.} =
        var `receivedRlp` = data
        var `receivedMsg` {.noinit.}: `msgRecord`
        `readParams`
        `awaitUserHandler`
        `callResolvedResponseFuture`

    finalOutput.add quote do:
      # This is a type featuring a single field for each message param:
      type `msgRecord`* = `msgRecordBody`

      # Add a helper template for accessing the message type:
      # e.g. p2p.hello:
      template `msgIdent`*(T: type `protoNameIdent`): typedesc = `msgRecord`

      # Add a helper template for obtaining the message Id for
      # a particular message type:
      template msgId*(T: type `msgRecord`): int = `msgId`

    var msgSendProc = n
    # TODO: check that the first param has the correct type
    msgSendProc.params[1][0] = msgRecipient

    # We change the return type of the proc to a Future.
    # If this is a request proc, the future will return the response record.
    let rt = if msgKind == rlpxRequest: responseRecord
             else: newIdentNode("int")
    msgSendProc.params[0] = newTree(nnkBracketExpr, newIdentNode("Future"), rt)

    let writeMsgId = if isSubprotocol:
      quote: `writeMsgId`(`protocol`, `msgId`, `msgRecipient`, `rlpWriter`)
    else:
      quote: `append`(`rlpWriter`, `msgId`)

    let sendProc = if msgKind == rlpxRequest: sendRequest else: sendMsg
    var sendCall = newCall(sendProc, msgRecipient, newCall(finish, rlpWriter))

    if msgKind == rlpxRequest:
      sendCall.add(responseRecord)

    # let paramCountNode = newLit(paramCount)
    msgSendProc.body = quote do:
      var `rlpWriter` = `initRlpWriter`()
      `writeMsgId`
      `startList`(`rlpWriter`, `paramCount`)
      `appendParams`
      return `sendCall`

    finalOutput.add msgSendProc
    msgThunksAndRegistrations.add newCall(bindSym("registerMsg"),
                                          protocol,
                                          newIntLitNode(msgId),
                                          newStrLitNode($n.name),
                                          thunkName)

  result = finalOutput
  result.add quote do:
    # One global variable per protocol holds the protocol run-time data
    var `protocol` = `newProtocol`(`protoName`, `version`)

    # Create a type actining as a pseudo-object representing the protocol (e.g. p2p)
    type `protoNameIdent`* = object

    # The protocol run-time data is available as a pseudo-field (e.g. `p2p.protocolInfo`)
    template protocolInfo*(P: type `protoNameIdent`): ProtocolInfo = `protocol`

  for n in body:
    case n.kind
    of {nnkCall, nnkCommand}:
      if eqIdent(n[0], "nextID"):
        # By default message IDs are assigned in increasing order
        # `nextID` can be used to skip some of the numeric slots
        if n.len == 2 and n[1].kind == nnkIntLit:
          nextId = n[1].intVal.int
        else:
          error("nextID expects a single int value", n)
      elif eqIdent(n[0], "requestResponse"):
        # `requestResponse` can be given a block of 2 or more procs.
        # The last one is considered to be a response message, while
        # all preceeding ones are requests triggering the response.
        # The system makes sure to automatically insert a hidden `reqID`
        # parameter used to discriminate the individual messages.
        block processReqResp:
          if n.len == 2 and n[1].kind == nnkStmtList:
            var procs = newSeq[NimNode](0)
            for def in n[1]:
              if def.kind == nnkProcDef:
                procs.add(def)
            if procs.len > 1:
              let responseMsgId = nextId + procs.len - 1
              let responseRecord = addMsgHandler(responseMsgId,
                                                 procs[^1],
                                                 msgKind = rlpxResponse)
              for i in 0 .. procs.len - 2:
                discard addMsgHandler(nextId + i, procs[i],
                                      msgKind = rlpxRequest,
                                      responseMsgId = responseMsgId,
                                      responseRecord = responseRecord)

              inc nextId, procs.len

              # we got all the way to here, so everything is fine.
              # break the block so it doesn't reach the error call below
              break processReqResp
          error("requestResponse expects a block with at least two proc definitions")
      else:
        error(repr(n) & " is not a recognized call in RLPx protocol definitions", n)

    of nnkAsgn:
      if eqIdent(n[0], "useRequestIds"):
        useRequestIds = $n[1] == "true"
      else:
        error(repr(n[0]) & " is not a recognized protocol option")

    of nnkTypeSection:
      result.add n
      for typ in n:
        if eqIdent(typ[0], "State"):
          stateType = genSym(nskType, protoName & "State")
          typ[0] = stateType
          result.add quote do:
            template State*(P: type `protoNameIdent`): typedesc =
              `stateType`

        elif eqIdent(typ[0], "NetworkState"):
          networkStateType = genSym(nskType, protoName & "NetworkState")
          typ[0] = networkStateType
          result.add quote do:
            template NetworkState*(P: type `protoNameIdent`): typedesc =
              `networkStateType`

        else:
          error("The only type names allowed within a RLPx protocol definition are 'State' and 'NetworkState'")


    of nnkProcDef:
      discard addMsgHandler(nextId, n)
      inc nextId

    else:
      error("illegal syntax in a RLPx protocol definition", n)

  result.add(msgThunksAndRegistrations)
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
             capabilities: seq[Capability],
             listenPort: uint,
             nodeId: array[RawPublicKeySize, byte]) =
    # peer.id = nodeId
    peer.dispatcher = getDispatcher(capabilities)

  proc disconnect(peer: Peer, reason: DisconnectionReason)

  proc ping(peer: Peer) =
    discard peer.pong()

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
  newSeq(p.protocolStates, rlpxProtocols.len)
  # XXX: initialize the sub-protocol states

proc initSecretState(hs: var Handshake, authMsg, ackMsg: openarray[byte],
                     p: Peer) =
  var secrets: ConnectionSecret
  check hs.getSecrets(authMsg, ackMsg, secrets)
  initSecretState(secrets, p.secretsState)
  burnMem(secrets)

proc rlpxConnect*(remote: Node, myKeys: KeyPair, listenPort: Port,
                  clientId: string): Future[Peer] {.async.} =
  new result
  result.remote = remote
  let ta = initTAddress(remote.node.address.ip, remote.node.address.tcpPort)
  try:
    result.transp = await connect(ta)

    var handshake = newHandshake({Initiator})
    handshake.host = myKeys

    var authMsg: array[AuthMessageMaxEIP8, byte]
    var authMsgLen = 0
    check authMessage(handshake, remote.node.pubkey, authMsg, authMsgLen)
    var res = result.transp.write(addr authMsg[0], authMsgLen)

    let initialSize = handshake.expectedLength
    var ackMsg = newSeqOfCap[byte](1024)
    ackMsg.setLen(initialSize)

    await result.transp.readExactly(addr ackMsg[0], len(ackMsg))

    var ret = handshake.decodeAckMessage(ackMsg)
    if ret == AuthStatus.IncompleteError:
      ackMsg.setLen(handshake.expectedLength)
      await result.transp.readExactly(addr ackMsg[initialSize],
                                      len(ackMsg) - initialSize)
      ret = handshake.decodeAckMessage(ackMsg)
    check ret

    initSecretState(handshake, ^authMsg, ackMsg, result)

    # if handshake.remoteHPubkey != remote.node.pubKey:
    #   raise newException(Exception, "Remote pubkey is wrong")

    discard result.hello(baseProtocolVersion, clientId, rlpxCapabilities,
                         uint(listenPort), myKeys.pubkey.getRaw())

    var response = await result.waitSingleMsg(p2p.hello)

    if not validatePubKeyInHello(response, remote.node.pubKey):
      warn "Remote nodeId is not its public key" # XXX: Do we care?

    connectionEstablished(result, response)
  except:
    if not isNil(result.transp):
      result.transp.close()

proc rlpxAccept*(transp: StreamTransport, myKeys: KeyPair,
                 clientId: string): Future[Peer] {.async.} =
  new result
  result.transp = transp
  var handshake = newHandshake({Responder})
  handshake.host = myKeys

  try:
    let initialSize = handshake.expectedLength
    var authMsg = newSeqOfCap[byte](1024)
    authMsg.setLen(initialSize)
    await transp.readExactly(addr authMsg[0], len(authMsg))
    var ret = handshake.decodeAuthMessage(authMsg)
    if ret == AuthStatus.IncompleteError: # Eip8 auth message is likely
      authMsg.setLen(handshake.expectedLength)
      await transp.readExactly(addr authMsg[initialSize],
                               len(authMsg) - initialSize)
      ret = handshake.decodeAuthMessage(authMsg)
    check ret

    var ackMsg: array[AckMessageMaxEIP8, byte]
    var ackMsgLen: int
    check handshake.ackMessage(ackMsg, ackMsgLen)
    var res = transp.write(addr ackMsg[0], ackMsgLen)

    initSecretState(handshake, authMsg, ^ackMsg, result)

    var response = await result.waitSingleMsg(p2p.hello)
    let listenPort = transp.localAddress().port
    discard result.hello(baseProtocolVersion, clientId,
                         rlpxCapabilities, listenPort.uint,
                         myKeys.pubkey.getRaw())

    if validatePubKeyInHello(response, handshake.remoteHPubkey):
      warn "Remote nodeId is not its public key" # XXX: Do we care?

    let port = Port(response.listenPort)
    let remote = transp.remoteAddress()
    let address = Address(ip: remote.address, tcpPort: remote.port,
                          udpPort: remote.port)
    result.remote = newNode(initEnode(handshake.remoteHPubkey, address))

    connectionEstablished(result, response)
  except:
    transp.close()

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

    useRequestIds = false

    proc foo(p: Peer, s: string, a, z: int) =
      p.state.messages += 1
      echo p.state(aaa).peerName

    proc bar(p: Peer, i: int, s: string)

  var p = Peer()
  discard p.bar(10, "test")

  when false:
    # The assignments below can be used to investigate if the RLPx procs
    # are considered GcSafe. The short answer is that they aren't, because
    # they dispatch into user code that might use the GC.
    type
      GcSafeDispatchMsg = proc (peer: Peer, msgId: int, msgData: var Rlp)

      GcSafeRecvMsg = proc (peer: Peer):
        Future[tuple[msgId: int, msgData: Rlp]] {.gcsafe.}

      GcSafeAccept = proc (transp: StreamTransport, myKeys: KeyPair):
        Future[Peer] {.gcsafe.}

    var
      dispatchMsgPtr = dispatchMsg
      recvMsgPtr: GcSafeRecvMsg = recvMsg
      acceptPtr: GcSafeAccept = rlpxAccept
