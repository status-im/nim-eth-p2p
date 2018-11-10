import
  deques, tables,
  package_visible_types,
  rlp, asyncdispatch2, eth_common/eth_types, eth_keys,
  ../enode, ../kademlia, ../discovery, ../options, ../rlpxcrypt

const
  useSnappy* = defined(useSnappy)

type
  EthereumNode* = ref object
    networkId*: uint
    chain*: AbstractChainDB
    clientId*: string
    connectionState*: ConnectionState
    keys*: KeyPair
    address*: Address
    peerPool*: PeerPool

    # Private fields:
    rlpxCapabilities*: seq[Capability]
    rlpxProtocols*: seq[ProtocolInfo]
    listeningServer*: StreamServer
    protocolStates*: seq[RootRef]
    discovery*: DiscoveryProtocol
    when useSnappy:
      protocolVersion*: uint

  Peer* = ref object
    remote*: Node
    network*: EthereumNode

    # Private fields:
    transport*: StreamTransport
    dispatcher*: Dispatcher
    lastReqId*: int
    secretsState*: SecretState
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    outstandingRequests*: seq[Deque[OutstandingRequest]]
    awaitedMessages*: seq[FutureBase]
    when useSnappy:
      snappyEnabled*: bool

  PeerPool* = ref object
    # Private fields:
    network*: EthereumNode
    keyPair*: KeyPair
    networkId*: uint
    minPeers*: int
    clientId*: string
    discovery*: DiscoveryProtocol
    lastLookupTime*: float
    connectedNodes*: Table[Node, Peer]
    connectingNodes*: HashSet[Node]
    running*: bool
    listenPort*: Port
    observers*: Table[int, PeerObserver]

  PeerObserver* = object
    onPeerConnected*: proc(p: Peer)
    onPeerDisconnected*: proc(p: Peer)

  Capability* = object
    name*: string
    version*: int

  UnsupportedProtocol* = object of Exception
    # This is raised when you attempt to send a message from a particular
    # protocol to a peer that doesn't support the protocol.

  MalformedMessageError* = object of Exception

  PeerDisconnected* = object of Exception
    reason*: DisconnectionReason

  UselessPeerError* = object of Exception

  ##
  ## Quasy-private types. Use at your own risk.
  ##

  ProtocolInfo* = ref object
    name*: string
    version*: int
    messages*: seq[MessageInfo]
    index*: int # the position of the protocol in the
                # ordered list of supported protocols

    # Private fields:
    peerStateInitializer*: PeerStateInitializer
    networkStateInitializer*: NetworkStateInitializer
    handshake*: HandshakeStep
    disconnectHandler*: DisconnectionHandler

  MessageInfo* = object
    id*: int
    name*: string

    # Private fields:
    thunk*: MessageHandler
    printer*: MessageContentPrinter
    requestResolver*: RequestResolver
    nextMsgResolver*: NextMsgResolver

  Dispatcher* = ref object # private
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
    protocolOffsets*: seq[int]
    messages*: seq[ptr MessageInfo]
    activeProtocols*: seq[ProtocolInfo]

  ##
  ## Private types:
  ##

  OutstandingRequest* = object
    id*: int
    future*: FutureBase
    timeoutAt*: uint64

  # Private types:
  MessageHandlerDecorator* = proc(msgId: int, n: NimNode): NimNode
  MessageHandler* = proc(x: Peer, msgId: int, data: Rlp): Future[void]
  MessageContentPrinter* = proc(msg: pointer): string
  RequestResolver* = proc(msg: pointer, future: FutureBase)
  NextMsgResolver* = proc(msgData: Rlp, future: FutureBase)
  PeerStateInitializer* = proc(peer: Peer): RootRef
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef
  HandshakeStep* = proc(peer: Peer): Future[void]
  DisconnectionHandler* = proc(peer: Peer,
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

