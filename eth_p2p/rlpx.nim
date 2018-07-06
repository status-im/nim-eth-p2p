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
  tables, deques, macros, sets, algorithm, hashes, times, random, options,
  asyncdispatch2, asyncdispatch2/timer,
  rlp, ranges/[stackarrays, ptr_arith], nimcrypto, chronicles,
  eth_keys, eth_common,
  kademlia, discovery, auth, rlpxcrypt, enode

type
  ConnectionState* = enum
    None,
    Connected,
    Disconnecting,
    Disconnected

  NetworkConnection* = ref object
    id: int
    listeningServer: StreamServer
    protocolStates: seq[RootRef]
    chainDb: AbstractChainDB
    keyPair: KeyPair
    address: Address
    clientId: string
    discovery: DiscoveryProtocol
    peerPool: PeerPool

  OutstandingRequest = object
    reqId: int
    future: FutureBase
    timeoutAt: uint64

  Peer* = ref object
    transp: StreamTransport
    dispatcher: Dispatcher
    nextReqId: int
    network: NetworkConnection
    secretsState: SecretState
    connectionState: ConnectionState
    remote*: Node
    protocolStates: seq[RootRef]
    outstandingRequests*: seq[Deque[OutstandingRequest]]

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

  MessageHandler* = proc(x: Peer, data: Rlp): Future[void]
  MessageContentPrinter* = proc(msg: pointer): string
  MessageFutureResolver* = proc(msg: pointer, future: FutureBase)

  MessageInfo* = object
    id*: int
    name*: string
    thunk*: MessageHandler
    printer*: MessageContentPrinter
    futureResolver*: MessageFutureResolver

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
    # `messages` holds a mapping from valid message IDs to their handler procs.
    #
    protocolOffsets: seq[int]
    messages: seq[ptr MessageInfo]

  RlpxMessageKind* = enum
    rlpxNotification,
    rlpxRequest,
    rlpxResponse

  UnsupportedProtocol* = object of Exception
    # This is raised when you attempt to send a message from a particular
    # protocol to a peer that doesn't support the protocol.

  MalformedMessageError* = object of Exception

logScope:
  topic = "rlpx"

const
  baseProtocolVersion = 4
  defaultReqTimeout = 10000

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

proc `$`*(p: Peer): string {.inline.} =
  $p.remote

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
  # TODO: sub-optimal solution until progress is made here:
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
        dest[index + i] = addr src[i]

    result.messages = newSeq[ptr MessageInfo](nextUserMsgId)
    devp2pProtocolInfo.messages.copyTo(result.messages, 0)

    for i in 0 ..< rlpxProtocols.len:
      if result.protocolOffsets[i] != -1:
        rlpxProtocols[i].messages.copyTo(result.messages, result.protocolOffsets[i])

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

proc messagePrinter[MsgType](msg: pointer): string =
  result = $(cast[ptr MsgType](msg)[])

proc messageFutureResolver[MsgType](msg: pointer, future: FutureBase) =
  var f = Future[Option[MsgType]](future)
  if not f.finished:
    if msg != nil:
      f.complete some(cast[ptr MsgType](msg)[])
    else:
      f.complete none(MsgType)
  else:
    # This future was already resolved, but let's do some sanity checks
    # here. The only reasonable explanation is that the request should
    # have timed out.
    if msg != nil:
      if f.read.isSome:
        doAssert false, "trying to resolve a request twice"
      else:
        doAssert false, "trying to resolve a timed out request with a value"
    else:
      if not f.read.isSome:
        doAssert false, "a request timed out twice"

proc registerMsg(protocol: var ProtocolInfo,
                 id: int, name: string,
                 thunk: MessageHandler,
                 printer: MessageContentPrinter,
                 futureResolver: MessageFutureResolver) =
  protocol.messages.add MessageInfo(id: id,
                                    name: name,
                                    thunk: thunk,
                                    printer: printer,
                                    futureResolver: futureResolver)

proc registerProtocol(protocol: ProtocolInfo) =
  # TODO: This can be done at compile-time in the future
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

  if msgId >= peer.dispatcher.messages.len: invalidIdError()
  let thunk = peer.dispatcher.messages[msgId].thunk
  if thunk == nil: invalidIdError()

  return thunk(peer, msgData)

proc sendMsg(p: Peer, data: BytesRange): Future[int] =
  # var rlp = rlpFromBytes(data)
  # echo "sending: ", rlp.read(int)
  # echo "payload: ", rlp.inspect
  var cipherText = encryptMsg(data, p.secretsState)
  return p.transp.write(cipherText)

proc registerRequest(peer: Peer,
                     timeout: int,
                     responseFuture: FutureBase,
                     responseMsgId: int): int =
  result = peer.nextReqId
  inc peer.nextReqId

  let timeoutAt = fastEpochTime() + uint64(timeout)
  let req = OutstandingRequest(reqId: result,
                               future: responseFuture,
                               timeoutAt: timeoutAt)
  peer.outstandingRequests[responseMsgId].addLast req

  # XXX: is this safe?
  let futureResolver = peer.dispatcher.messages[responseMsgId].futureResolver
  proc timeoutExpired(udata: pointer) = futureResolver(nil, responseFuture)

  addTimer(timeoutAt, timeoutExpired, nil)

proc resolveResponseFuture(peer: Peer, msgId: int, msg: pointer, reqId: int) =
  logScope:
    msg = peer.dispatcher.messages[msgId].name
    msgContents = peer.dispatcher.messages[msgId].printer(msg)
    receivedReqId = reqId
    remotePeer = peer.remote

  template resolve(future) =
    peer.dispatcher.messages[msgId].futureResolver(msg, future)

  template outstandingReqs: auto =
    peer.outstandingRequests[msgId]

  if reqId == -1:
    # XXX: This is a response from an ETH-like protocol that doesn't feature
    # request IDs. Handling the response is quite tricky here because this may
    # be a late response to an already timed out request or a valid response
    # from a more recent one.
    #
    # We can increase the robustness by recording enough features of the
    # request so we can recognize the matching response, but this is not very
    # easy to do because our peers are allowed to send partial responses.
    #
    # A more generally robust approach is to maintain a set of the wanted
    # data items and then to periodically look for items that have been
    # requested long time ago, but are still missing. New requests can be
    # issues for such items potentially from another random peer.
    var expiredRequests = 0
    for req in outstandingReqs:
      if not req.future.finished: break
      inc expiredRequests
    outstandingReqs.shrink(fromFront = expiredRequests)
    if outstandingReqs.len > 0:
      let oldestReq = outstandingReqs.popFirst
      assert oldestReq.reqId == -1
      resolve oldestReq.future
    else:
      debug "late or duplicate reply for a RLPx request"
  else:
    # TODO: This is not completely sound because we are still using a global
    # `reqId` sequence (the problem is that we might get a response ID that
    # matches a request ID for a different type of request). To make the code
    # correct, we can use a separate sequence per response type, but we have
    # to first verify that the other Ethereum clients are supporting this
    # correctly (because then, we'll be reusing the same reqIds for different
    # types of requests). Alternatively, we can assign a separate interval in
    # the `reqId` space for each type of response.
    if reqId >= peer.nextReqId:
      warn "RLPx response without a matching request"
      return

    var idx = 0
    while idx < outstandingReqs.len:
      template req: auto = outstandingReqs()[idx]

      if req.future.finished:
        assert req.timeoutAt < fastEpochTime()
        # Here we'll remove the expired request by swapping
        # it with the last one in the deque (if necessary):
        if idx != outstandingReqs.len - 1:
          req = outstandingReqs.popLast
        else:
          outstandingReqs.shrink(fromEnd = 1)
          # This was the last item, so we don't have any
          # more work to do:
          return

      if req.reqId == reqId:
        resolve req.future
        # Here we'll remove the found request by swapping
        # it with the last one in the deque (if necessary):
        if idx != outstandingReqs.len - 1:
          req = outstandingReqs.popLast
        else:
          outstandingReqs.shrink(fromEnd = 1)
        return

      inc idx

    debug "late or duplicate reply for a RLPx request"

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
      # TODO: this should be `enterList`
      nextMsgData = nextMsgData.listElem(0)
    await peer.dispatchMsg(nextMsgId, nextMsgData)
    if nextMsgId == wantedId:
      return nextMsgData.read(MsgType)

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

proc popTimeoutParam(n: NimNode): NimNode =
  var lastParam = n.params[^1]
  if eqIdent(lastParam[0], "timeout"):
    if lastParam[2].kind == nnkEmpty:
      macros.error "You must specify a default value for the `timeout` parameter", lastParam
    result = lastParam
    n.params.del(n.params.len - 1)

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
    Peer = bindSym "Peer"
    Option = bindSym "Option"
    # XXX: Binding the int type causes instantiation failure for some reason
    # Int = bindSym "int"
    Int = newIdentNode "int"
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
    messagePrinter = bindSym "messagePrinter"
    messageFutureResolver = bindSym "messageFutureResolver"

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
      reqTimeout: NimNode
      rlpWriter = genSym(nskVar, "writer")
      appendParams = newNimNode(nnkStmtList)
      sentReqId = genSym(nskLet, "reqId")

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
      # If the request proc has a default timeout specified, remove it from
      # the signature for now so we can generate the `thunk` proc without it.
      # The parameter will be added back later only for to the sender proc.
      # When the timeout is not specified, we use a default one.
      reqTimeout = popTimeoutParam(n)
      if reqTimeout == nil:
        reqTimeout =  newTree(nnkIdentDefs,
                              genSym(nskParam, "timeout"),
                              Int, newLit(defaultReqTimeout))

      # Each request is registered so we can resolve it when the response
      # arrives. There are two types of protocols: LES-like protocols use
      # explicit `reqId` sent over the wire, while the ETH wire protocol
      # assumes there is one outstanding request at a time (if there are
      # multiple requests we'll resolve them in FIFO order).
      let registerRequestCall = newCall(registerRequest, msgRecipient,
                                                         reqTimeout[0],
                                                         resultIdent,
                                                         newLit(responseMsgId))
      if useRequestIds:
        inc paramCount
        appendParams.add quote do:
          new `resultIdent`
          let `sentReqId` = `registerRequestCall`
          `append`(`rlpWriter`, `sentReqId`)
      else:
        appendParams.add quote do:
          discard `registerRequestCall`
    of rlpxResponse:
      if useRequestIds:
        var reqId = genSym(nskLet, "reqId")

        # Messages using request Ids
        readParams.add quote do:
          let `reqId` = `read`(`receivedRlp`, int)

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

    # Add a timeout parameter for all request procs
    if msgKind == rlpxRequest: msgSendProc.params.add reqTimeout

    # We change the return type of the sending proc to a Future.
    # If this is a request proc, the future will return the response record.
    let rt = if msgKind != rlpxRequest: Int
             else: newTree(nnkBracketExpr, Option, responseRecord)
    msgSendProc.params[0] = newTree(nnkBracketExpr, newIdentNode("Future"), rt)

    let writeMsgId = if isSubprotocol:
      quote: `writeMsgId`(`protocol`, `msgId`, `msgRecipient`, `rlpWriter`)
    else:
      quote: `append`(`rlpWriter`, `msgId`)

    var sendCall = newCall(sendMsg, msgRecipient, newCall(finish, rlpWriter))
    let senderEpilogue = if msgKind == rlpxRequest:
      # In RLPx requests, the returned future was allocated here and passed
      # to `registerRequest`. It's already assigned to the result variable
      # of the proc, so we just wait for the sending operation to complete
      # and we return in a normal way. (the waiting is done, so we can catch
      # any possible errors).
      quote: discard waitFor(`sendCall`)
    else:
      # In normal RLPx messages, we are returning the future returned by the
      # `sendMsg` call.
      quote: return `sendCall`

    # let paramCountNode = newLit(paramCount)
    msgSendProc.body = quote do:
      var `rlpWriter` = `initRlpWriter`()
      `writeMsgId`
      `startList`(`rlpWriter`, `paramCount`)
      `appendParams`
      `senderEpilogue`

    finalOutput.add msgSendProc

    msgThunksAndRegistrations.add(
      newCall(bindSym("registerMsg"),
              protocol,
              newIntLitNode(msgId),
              newStrLitNode($n.name),
              thunkName,
              newTree(nnkBracketExpr, messagePrinter, msgRecord),
              newTree(nnkBracketExpr, messageFutureResolver, msgRecord)))

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
          macros.error("nextID expects a single int value", n)
      elif eqIdent(n[0], "requestResponse"):
        # `requestResponse` can be given a block of 2 or more procs.
        # The last one is considered to be a response message, while
        # all preceeding ones are requests triggering the response.
        # The system makes sure to automatically insert a hidden `reqId`
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
          macros.error("requestResponse expects a block with at least two proc definitions")
      else:
        macros.error(repr(n) & " is not a recognized call in RLPx protocol definitions", n)

    of nnkAsgn:
      if eqIdent(n[0], "useRequestIds"):
        useRequestIds = $n[1] == "true"
      else:
        macros.error(repr(n[0]) & " is not a recognized protocol option")

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
          macros.error("The only type names allowed within a RLPx protocol definition are 'State' and 'NetworkState'")


    of nnkProcDef:
      discard addMsgHandler(nextId, n)
      inc nextId

    else:
      macros.error("illegal syntax in a RLPx protocol definition", n)

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

  # The dispatcher has determined our message ID sequence.
  # For each message ID, we allocate a potential slot for
  # tracking responses to requests.
  # (yes, some of the slots won't be used).
  p.outstandingRequests.newSeq(p.dispatcher.messages.len)
  for d in mitems(p.outstandingRequests): d = initDeque[OutstandingRequest](0)

  p.nextReqId = 1

  # p.id = h.nodeId
  newSeq(p.protocolStates, rlpxProtocols.len)

  p.connectionState = Connected
  # TODO: initialize the sub-protocol states

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

    asyncCheck result.hello(baseProtocolVersion, clientId, rlpxCapabilities,
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

# PeerPool attempts to keep connections to at least min_peers
# on the given network.

const
  lookupInterval = 5
  connectLoopSleepMs = 2000

proc newPeerPool*(chainDb: AbstractChainDB, networkId: int, keyPair: KeyPair,
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
    debug "skipping_connection_to_already_connected_peer", remote
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
    debug "pool already connected to enough peers (sleeping)", count = p.connectedNodes
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

proc processIncoming(server: StreamServer,
                     remote: StreamTransport): Future[void] {.async, gcsafe.} =
  var p2p = getUserData[NetworkConnection](server)
  let peerfut = remote.rlpxAccept(p2p.keyPair, p2p.clientId)
  yield peerfut
  if not peerfut.failed:
    let peer = peerfut.read()
    echo "TODO: Add peer to the pool..."
  else:
    echo "Could not establish connection with incoming peer ",
         $remote.remoteAddress()
    remote.close()

proc connectToNetwork*(keyPair: KeyPair,
                       address: Address,
                       chainDb: AbstractChainDB,
                       bootstrapNodes: openarray[ENode],
                       clientId: string,
                       networkId: int,
                       startListening = true): NetworkConnection =
  new result
  result.id = networkId
  result.chainDb = chainDb
  result.keyPair = keyPair
  result.address = address
  result.clientId = clientId
  result.discovery = newDiscoveryProtocol(keyPair.seckey, address,
                                          bootstrapNodes)
  result.peerPool = newPeerPool(chainDb, networkId, keyPair, result.discovery,
                                clientId, address.tcpPort)

  let ta = initTAddress(address.ip, address.tcpPort)
  result.listeningServer = createStreamServer(ta, processIncoming,
                                              {ReuseAddr},
                                              udata = result)

  if startListening:
    result.listeningServer.start()

proc startListening*(s: NetworkConnection) =
  s.listeningServer.start()

proc stopListening*(s: NetworkConnection) =
  s.listeningServer.stop()

when isMainModule:
  import rlp

  rlpxProtocol aaa, 1:
    type State = object
      peerName: string

    requestResponse:
      proc aaaReq(p: Peer, n: int) =
        echo "got req ", n

      proc aaaRes(p: Peer, data: string) =
        echo "got response ", data

    proc hi(p: Peer, name: string) =
      p.state.peerName = name
      var r = await p.aaaReq(10)
      echo r.get.data

  rlpxProtocol bbb, 1:
    type State = object
      messages: int

    useRequestIds = false

    proc foo(p: Peer, s: string, a, z: int) =
      p.state.messages += 1
      echo p.state(aaa).peerName

    proc bar(p: Peer, i: int, s: string)

    requestResponse:
      proc bbbReq(p: Peer, n: int, timeout = 3000) =
        echo "got req ", n

      proc bbbRes(p: Peer, data: string) =
        echo "got response ", data

  var p = Peer()
  discard p.bar(10, "test")
  var resp = waitFor p.bbbReq(10)
  echo "B response: ", resp.get.data

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
