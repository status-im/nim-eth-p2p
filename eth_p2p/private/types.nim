import
  deques, tables,
  package_visible_types,
  rlp, asyncdispatch2, eth_common/eth_types, eth_keys,
  ../enode, ../kademlia, ../discovery, ../options, ../rlpxcrypt

packageTypes:
  type
    EthereumNode* = ref object
      networkId*: uint
      chain*: AbstractChainDB
      clientId*: string
      connectionState*: ConnectionState
      keys*: KeyPair
      address*: Address
      rlpxCapabilities: seq[Capability]
      rlpxProtocols: seq[ProtocolInfo]
      listeningServer: StreamServer
      protocolStates: seq[RootRef]
      discovery: DiscoveryProtocol
      peerPool*: PeerPool
      when defined(useSnappy):
        protocolVersion: uint

    Peer* = ref object
      transport: StreamTransport
      dispatcher: Dispatcher
      lastReqId*: int
      network*: EthereumNode
      secretsState: SecretState
      connectionState: ConnectionState
      remote*: Node
      protocolStates: seq[RootRef]
      outstandingRequests: seq[Deque[OutstandingRequest]]
      awaitedMessages: seq[FutureBase]
      when defined(useSnappy):
        snappyEnabled: bool

    OutstandingRequest = object
      id: int
      future: FutureBase
      timeoutAt: uint64

    PeerPool* = ref object
      network: EthereumNode
      keyPair: KeyPair
      networkId: uint
      minPeers: int
      clientId: string
      discovery: DiscoveryProtocol
      lastLookupTime: float
      connectedNodes: Table[Node, Peer]
      connectingNodes: HashSet[Node]
      running: bool
      listenPort*: Port
      observers: Table[int, PeerObserver]

    MessageInfo* = object
      id*: int
      name*: string
      thunk*: MessageHandler
      printer*: MessageContentPrinter
      requestResolver: RequestResolver
      nextMsgResolver: NextMsgResolver

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
      peerStateInitializer: PeerStateInitializer
      networkStateInitializer: NetworkStateInitializer
      handshake: HandshakeStep
      disconnectHandler: DisconnectionHandler

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
      activeProtocols: seq[ProtocolInfo]

    PeerObserver* = object
      onPeerConnected*: proc(p: Peer)
      onPeerDisconnected*: proc(p: Peer)

    MessageHandlerDecorator = proc(msgId: int, n: NimNode): NimNode
    MessageHandler = proc(x: Peer, msgId: int, data: Rlp): Future[void]
    MessageContentPrinter = proc(msg: pointer): string
    RequestResolver = proc(msg: pointer, future: FutureBase)
    NextMsgResolver = proc(msgData: Rlp, future: FutureBase)
    PeerStateInitializer = proc(peer: Peer): RootRef
    NetworkStateInitializer = proc(network: EthereumNode): RootRef
    HandshakeStep = proc(peer: Peer): Future[void]
    DisconnectionHandler = proc(peer: Peer,
                                reason: DisconnectionReason): Future[void] {.gcsafe.}

    RlpxMessageKind* = enum
      rlpxNotification,
      rlpxRequest,
      rlpxResponse

    ConnectionState* = enum
      None,
      Connecting,
      Connected,
      Disconnecting,
      Disconnected

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

    UnsupportedProtocol* = object of Exception
      # This is raised when you attempt to send a message from a particular
      # protocol to a peer that doesn't support the protocol.

    MalformedMessageError* = object of Exception

    PeerDisconnected* = object of Exception
      reason*: DisconnectionReason

    UselessPeerError* = object of Exception

