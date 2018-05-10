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
  macros, sets, algorithm, async, asyncnet, asyncfutures,
  hashes, rlp, ranges/[stackarrays, ptr_arith], eth_keys,
  ethereum_types, kademlia, discovery, auth, rlpxcrypt

type
  P2PNodeId = MDigest[512]

  ConnectionState = enum
    None,
    Connected,
    Disconnecting,
    Disconnected

  Peer* = ref object
    id: P2PNodeId # XXX: not fillet yed
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
    # REVIEW: why bother? there aren't millions of peers anyway, so why not
    #         keep it simple and keep this per peer? this just looks like
    #         it introduces lots of book-keeping and opportunities for logic
    #         errors. This also seems like the smallest piece of information
    #         to share - we still have to keep per-peer, per protocol state
    #
    # `protocolOffsets` will hold one slot of each locally supported
    # protocol. If the other peer also supports the protocol, the stored
    # offset indicates the numeric value of the first message of the protocol
    # (for this particular connection). If the other peer doesn't support the
    # particular protocol, the stored offset is -1.
    # REVIEW: The alternative is to store a messagehandler that does nothing -
    #         or logs the call or returns a "ignored" status - this tends
    #         to simplify code and remove unnecessary error handling and bounds
    #         checking etc..
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

# REVIEW these globals will prevent us from using rlpx as a library, for example
#        when setting up a simulation or test - a major use case for research
#        I think a hard no-thanks stance on mutable globals is valuable if we
#        want to pursue a library-first approach
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
  # REVIEW: as long as there's an option to disable certain protocols at run time,
  #         per globals-comment above
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
    # REVIEW: what's the use case for this exception? when is it expected that
    #         someone will catch it and use the type to meaningfully handle the
    #         error? else might just assert - seems like a logic error if this happens
    #         and sending the message anyway seems harmless
    raise newException(UnsupportedProtocol,
                       p.nameStr & " is not supported by peer " & $peer.id)
  rlpOut.append(baseMsgId + msgId)

proc dispatchMsg(peer: Peer, msgId: int, msgData: var Rlp) =
  # REVIEW: who will call dispatchMsg? right now, only nextMsg, which more looks
  #         like a way to short-circuit message dispatching..
  template invalidIdError: untyped =
    raise newException(ValueError,
      "RLPx message with an invalid id " & $msgId &
      " on a connection supporting " & peer.dispatcher.describeProtocols)

  if msgId >= peer.dispatcher.thunks.len: invalidIdError()
  let thunk = peer.dispatcher.thunks[msgId]
  if thunk == nil: invalidIdError()

  thunk(peer, msgData)

proc send(p: Peer, data: BytesRange): Future[void] =
  var cipherText = encryptMsg(data, p.secretsState)
  result = p.socket.send(addr cipherText[0], cipherText.len)

proc getMsgLen(header: RlpxHeader): int =
  32

proc fullRecvInto(s: AsyncSocket, buffer: pointer, bufferLen: int) {.async.} =
  # XXX: This should be a library function
  var receivedBytes = 0
  while receivedBytes < bufferLen:
    receivedBytes += await s.recvInto(buffer.shift(receivedBytes),
                                      bufferLen - receivedBytes)

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
  # REVIEW: or pass it in, allowing the caller to choose - they'll likely be in a
  #      better position to decide if buffer should be reused or not. this will
  #      also be useuful for chunked messages where part of the buffer may have
  #      been processed and needs filling in
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
  # REVIEW: it's unclear to me how prioritization between regular
  #         dispatching and nextMsg style dispatching should happen,
  #         also between multiple nextMsg calls - who gets the
  #         message first?
  #         discardOthers looks like an easy way to introduce
  #         "deadlocks" if there are two discardOthers calls in
  #         flight
  #         an alternative here would be a super-state-machine:
  #         you register message handlers not only for a peer but
  #         also for a particualar peer state - this would allow
  #         us to create states for the peer (pre-auth, hello,
  #         regular-comms, tear-down), keeping it clear which
  #         messages are handled in which states, for example when
  #         auditing the implementation - this could probably be
  #         the same state enum as ConnectionState - it doesn't really
  #         matter if we're disconnected or connected-but-authenticating,
  #         we still won't handle most messages..
  #         another thing to consider once you get into request-
  #         response is that you also have to handle the usual
  #         suspects of async messaging: timeouts, arrivals of
  #         response after the timeout, etc
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
      inc nextId
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

      # implement sending proc
      for param, paramType in n.typedParams(skip = 1):
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

      n.body = quote do:
        var `rlpWriter` = `initRlpWriter`()
        `writeMsgId`
        `appendParams`
        return `send`(`peer`, `finish`(`rlpWriter`))

      result.add n
      result.add newCall(bindSym("registerMsg"),
                         protocol,
                         newIntLitNode(nextId),
                         newStrLitNode($n.name),
                         thunkName)

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
             nodeId: P2PNodeId) =
    peer.id = nodeId
    peer.dispatcher = getDispatcher(capabilities)

  proc disconnect(peer: Peer, reason: DisconnectionReason)

  proc ping(peer: Peer)

  proc pong(peer: Peer) =
    discard

import typetraits

proc rlpxConnect*(myKeys: KeyPair, remote: Node): Future[Peer] {.async.} =
  # TODO: Make sure to close the socket in case of exception
  result.socket = newAsyncSocket()
  await result.socket.connect($remote.node.address.ip, remote.node.address.tcpPort)

  const encryptionEnabled = true

  template check(body: untyped) =
    let c = body
    if c != AuthStatus.Success:
      raise newException(Exception, "Error: " & $c)

  template `^`(arr): auto =
    # passes a stack array with a matching `arrLen`
    # variable as an open array
    arr.toOpenArray(0, `arr Len` - 1)

  var handshake = newHandshake({Initiator})
  handshake.host.seckey = myKeys.seckey
  handshake.host.pubkey = myKeys.pubKey

  var authMsg: array[AuthMessageMaxEIP8, byte]
  var authMsgLen = 0
  check authMessage(handshake, remote.node.pubkey, authMsg, authMsgLen,
                    encrypt = encryptionEnabled)

  await result.socket.send(addr authMsg[0], authMsgLen)

  var ackMsg: array[AckMessageMaxEIP8, byte]
  let ackMsgLen = handshake.ackSize(encrypt = encryptionEnabled)
  await result.socket.fullRecvInto(addr ackMsg, ackMsgLen)

  check handshake.decodeAckMessage(^ackMsg)
  var secrets: ConnectionSecret
  check handshake.getSecrets(^authMsg, ^ackMsg, secrets)
  initSecretState(secrets, result.secretsState)

  var
    # XXX: TODO: get these from somewhere
    nodeId: P2PNodeId
    listeningPort = uint 0

  discard hello(result, baseProtocolVersion, clienId,
                gCapabilities, listeningPort, nodeId)

  var response = await result.nextMsg(p2p.hello, discardOthers = true)
  result.dispatcher = getDispatcher(response.capabilities)
  result.id = response.nodeId
  result.connectionState = Connected
  result.remote = remote
  newSeq(result.protocolStates, gProtocols.len)
  # XXX: initialize the sub-protocol states

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

