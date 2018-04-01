import
  macros, sets, algorithm, async, asyncnet, hashes, rlp, ecc,
  ethereum_types, kademlia, discovery, auth

type
  Peer* = ref object
    id: NodeId # XXX: not fillet yed
    socket: AsyncSocket
    dispatcher: Dispatcher
    # privKey: AesKey
    networkId: int
    sessionSecrets: ConnectionSecret

  MessageHandler* = proc(x: Peer, data: var Rlp)

  MessageDesc* = object
    id*: int
    name*: string
    thunk*: MessageHandler

  CapabilityName* = array[3, char]

  Capability* = object
    name*: CapabilityName
    version*: int

  Protocol* = ref object
    name*: CapabilityName
    version*: int
    messages*: seq[MessageDesc]
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

  KeyPair* = object
    # XXX: This should probably be in eth_keys
    pubKey*: PublicKey
    privKey*: PrivateKey

const
  baseProtocolVersion = 4
  clienId = "Nimbus 0.1.0"
  maxUInt24 = (not uint32(0)) shl 8

var
  gProtocols = newSeq[Protocol](0)
  gDispatchers = initSet[Dispatcher]()
  devp2p: Protocol

# Dispatcher
#

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

proc getDispatcher(otherPeerCapabilities: var openarray[Capability]): Dispatcher =
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

# Protocol
#

proc newProtocol(name: string, version: int): Protocol =
  new result
  result.name[0] = name[0]
  result.name[1] = name[1]
  result.name[2] = name[2]
  result.version = version
  result.messages = @[]

proc nameStr*(p: Protocol): string =
  result = newStringOfCap(3)
  for c in p.name: result.add(c)

proc cmp*(lhs, rhs: Protocol): int {.inline.} =
  for i in 0..2:
    if lhs.name[i] != rhs.name[i]:
      return int16(lhs.name[i]) - int16(rhs.name[i])
  return 0

proc registerMessage(protocol: var Protocol,
                     id: int, name: string, thunk: MessageHandler) =
  protocol.messages.add MessageDesc(id: id, name: name, thunk: thunk)

proc registerProtocol(protocol: Protocol) =
  # XXX: This can be done at compile-time in the future
  if protocol.version > 0:
    gProtocols.insert(protocol, lowerBound(gProtocols, protocol))
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

proc append*(rlpWriter: var RlpWriter, p: Protocol) =
  append(rlpWriter, (p.nameStr, p.version))

proc read*(rlp: var Rlp, T: type Protocol): Protocol =
  let cap = rlp.read(Capability)
  for p in gProtocols:
    if p.name == cap.name and p.version == cap.version:
      return p
  # XXX: This shouldn't return nil probably, but rather
  # an empty Protocol object
  return nil

# Message composition and encryption
#

proc writeMessageId(p: Protocol, msgId: int, peer: Peer, rlpOut: var RlpWriter) =
  let baseMsgId = peer.dispatcher.protocolOffsets[p.index]
  if baseMsgId == -1:
    raise newException(UnsupportedProtocol,
                       p.nameStr & " is not supported by peer " & $peer.id)
  rlpOut.append(baseMsgId + msgId)

proc updateMac(mac: var openarray[byte], key: openarray[byte], bytes: openarray[byte]) =
  # XXX TODO: implement this
  discard

proc send(p: Peer, data: BytesRange) =
  var header: array[32, byte]
  if data.len > int(maxUInt24):
    raise newException(OverflowError, "RLPx message size exceeds limit")

  # write the frame size in the first 3 bytes of the header
  header[0] = byte(data.len shl 16)
  header[1] = byte(data.len shl 8)
  header[2] = byte(data.len)

  # encrypt(addr header[0], 16)
  # TODO

  # update mac from first 16 bytes
  updateMac(p.sessionSecrets.egressMac,
            p.sessionSecrets.macKey,
            header.toOpenArray(0, 16))

  # write the mac in the second 16 bytes
  header[16..31] = p.sessionSecrets.egressMac[0..15]


  discard """
      def encrypt(self, header: bytes, frame: bytes) -> bytes:
          if len(header) != HEADER_LEN:
              raise ValueError("Unexpected header length: {}".format(len(header)))

          header_ciphertext = self.aes_enc.update(header)
          mac_secret = self.egress_mac.digest()[:HEADER_LEN]
          self.egress_mac.update(sxor(self.mac_enc(mac_secret), header_ciphertext))
          header_mac = self.egress_mac.digest()[:HEADER_LEN]

          frame_ciphertext = self.aes_enc.update(frame)
          self.egress_mac.update(frame_ciphertext)
          fmac_seed = self.egress_mac.digest()[:HEADER_LEN]

          mac_secret = self.egress_mac.digest()[:HEADER_LEN]
          self.egress_mac.update(sxor(self.mac_enc(mac_secret), fmac_seed))
          frame_mac = self.egress_mac.digest()[:HEADER_LEN]

          return header_ciphertext + header_mac + frame_ciphertext + frame_mac
  """

proc dispatchMessage(connection: Peer, msg: BytesRange) =
  # This proc dispatches an already decrypted message

  var rlp = rlpFromBytes(msg)
  let msgId = rlp.read(int)

  template invalidIdError: untyped =
    raise newException(ValueError,
      "RLPx message with an invalid id " & $msgId &
      " on a connection supporting " & connection.dispatcher.describeProtocols)

  if msgId >= connection.dispatcher.thunks.len: invalidIdError()
  let thunk = connection.dispatcher.thunks[msgId]
  if thunk == nil: invalidIdError()

  thunk(connection, rlp)

iterator typedParams(n: PNimrodNode, skip = 0): (PNimrodNode, PNimrodNode) =
  for i in (1 + skip) ..< n.params.len:
    let paramNodes = n.params[i]
    let paramType = paramNodes[^2]

    for j in 0 .. < (paramNodes.len-2):
      yield (paramNodes[j], paramType)

macro rlpxProtocol*(name: static[string],
                    version: static[int],
                    body: untyped): untyped =
  var
    nextId = BiggestInt 0
    protocol = genSym(nskVar)
    newProtocol = bindSym "newProtocol"
    rlpFromBytes = bindSym "rlpFromBytes"
    read = bindSym "read"
    initRlpWriter = bindSym "initRlpWriter"
    finish = bindSym "finish"
    append = bindSym "append"
    send = bindSym "send"
    Peer = bindSym "Peer"
    writeMessageId = bindSym "writeMessageId"
    isSubprotocol = version > 0

  result = newNimNode(nnkStmtList)
  result.add quote do:
    var `protocol` = `newProtocol`(`name`, `version`)

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
    of nnkProcDef:
      inc nextId
      let name = n.name.ident

      var
        thunkName = newNilLit()
        rlpWriter = genSym(nskVar, "writer")
        appendParams = newNimNode(nnkStmtList)
        peer = genSym(nskParam, "peer")

      if n.body.kind != nnkEmpty:
        # implement receiving thunk
        var
          nCopy = n.copyNimTree
          rlp = genSym(nskParam, "rlp")
          connection = genSym(nskParam, "connection")

        nCopy.name = genSym(nskProc, $name)
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

        thunkName = newIdentNode($name & "_thunk")
        var thunk = quote do:
          proc `thunkName`(`connection`: `Peer`, `rlp`: var Rlp) =
            `readParams`
            `callUserProc`

        result.add nCopy, thunk

      # implement sending proc
      for param, paramType in n.typedParams(skip = 1):
        appendParams.add quote do:
          `append`(`rlpWriter`, `param`)

      # XXX TODO: check that the first param has the correct type
      n.params[1][0] = peer

      let writeMsgId = if isSubprotocol:
        quote: `writeMessageId`(`protocol`, `nextId`, `peer`, `rlpWriter`)
      else:
        quote: `append`(`rlpWriter`, `nextId`)

      n.body = quote do:
        var `rlpWriter` = `initRlpWriter`()
        `writeMsgId`
        `appendParams`
        `send`(`peer`, `finish`(`rlpWriter`))

      result.add n
      result.add newCall(bindSym("registerMessage"),
                         protocol,
                         newIntLitNode(nextId),
                         newStrLitNode($n.name),
                         thunkName)

    else:
      error("illegal syntax in a RLPx protocol definition", n)

  result.add newCall(bindSym("registerProtocol"), protocol)
  echo repr(result)

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

rlpxProtocol("p2p", 0):

  proc hello(peer: Peer,
             version: uint,
             clientId: string,
             capabilities: openarray[Protocol],
             listenPort: uint,
             nodeId: MDigest[512]
             ) =
    discard

  proc disconnect(peer: Peer, reason: DisconnectionReason)

  proc ping(peer: Peer)

  proc pong(peer: Peer) =
    discard

proc rlpxConnect*(keys: KeyPair, address: Address): Future[Peer] {.async.} =
  result.socket = newAsyncSocket()
  await result.socket.connect($address.ip, address.tcpPort)

  var initiator = newHandshake({Initiator})
  initiator.host.seckey = keys.privKey
  initiator.host.pubkey = keys.pubKey

  var authPlain: PlainAuthMessage
  var authCiphertext: AuthMessage

  template check(body: untyped) =
    let c = body
    if c != AuthStatus.Success:
      raise newException(Exception, "Error: " & $c)

  check authMessage(initiator, keys.pubKey, authPlain)
  check encryptAuthMessage(authPlain, authCiphertext, keys.pubKey)
  await result.socket.send(addr authCiphertext[0], sizeof(authCiphertext))

  var authAck: AuthAckMessage
  let receivedBytes = await result.socket.recvInto(addr authAck, sizeof(authAck))

  if receivedBytes != sizeof(AuthAckMessage):
    # XXX: this handling is not perfect, we should probably retry until the
    # correct number of bytes are read!
    raise newException(MalformedMessageError, "AuthAck message has incorrect size")

  check initiator.decodeAckMessage(authAck)
  check initiator.getSecrets(authCiphertext, authAck, result.sessionSecrets)

  var
    # XXX: TODO
    nodeId: MDigest[512]
    listeningPort = uint 0

  hello(result, baseProtocolVersion, clienId, gProtocols, listeningPort, nodeId)

when isMainModule:
  import rlp

  rlpxProtocol("test", 1):
    proc foo(p: Peer, s: string, a, z: int) =
      echo s

    proc bar(p: Peer, i: int, s: string)

  var p = Peer()
  p.bar(10, "test")

