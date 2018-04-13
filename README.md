# nim-eth-p2p [![Build Status](https://travis-ci.org/status-im/nim-eth-p2p.svg?branch=master)](https://travis-ci.org/status-im/nim-eth-p2p) [![Build status](https://ci.appveyor.com/api/projects/status/i4txsa2pdyaahmn0/branch/master?svg=true)](https://ci.appveyor.com/project/cheatfate/nim-eth-p2p/branch/master)

[[Nim]] Ethereum P2P protocol implementation

## RLPx

[RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md) is the
high-level protocol for exchanging messages between peers in the Ethereum
network. Most of the client code of this library should not be concerned
with the implementation details of the underlying protocols and should use
the high-level APIs described in this section.

To obtain a RLPx connection, use the proc `rlpxConnect` supplying the
id of another node in the network. On success, the proc will return a
`Peer` object representing the connection. Each of the RLPx sub-protocols
consists of a set of strongly-typed messages, which are represented by
this library as regular Nim procs that can be executed over the `Peer`
object (more on this later).

### Defining RLPx sub-protocols

The sub-protocols are defined with the `rlpxProtocol` macro. It will accept
a 3-letter identifier for the protocol and the current protocol version:

Here is how the [DevP2P wire protocol](https://github.com/ethereum/wiki/wiki/%C3%90%CE%9EVp2p-Wire-Protocol) might look like:

``` nim
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
    echo "received pong from ", peer.id
```

#### Sending messages

To send a particular message to a particular peer, just call the
corresponding proc over the `Peer` object:

``` nim
peer.hello(4, "Nimbus 1.0", ...)
peer.ping()
```

#### Receiving messages

Once a connection is established, incoming messages in RLPx may appear in
arbitrary order, because the sub-protocols may be multiplexed over a single
underlying connection. For this reason, the library assumes that the incoming
messages will be dispatched automatically to their corresponding handlers,
appearing in the protocol definition. The protocol implementations are expected
to maintain a state and to act like a state machine handling the incoming messages.
To achieve this, each protocol may define a `State` object that can be accessed as
a `state` field of the `Peer` object:

``` nim
rlpxProtocol abc, 1:
  type State = object
    receivedMsgsCount: int

  proc incomingMessage(p: Peer) =
    p.state.receivedMsgsCount += 1

```

Sometimes, you'll need to access the state of another protocol. To do this,
specify the protocol identifier to the `state` accessor:

``` nim
  echo "ABC protocol messages: ", peer.state(abc).receivedMsgCount
```

While the state machine approach is the recommended way of implementing
sub-protocols, sometimes in imperative code it may be easier to wait for
a particular response message after sending a certain request.

This is enabled by the helper proc `nextMsg`:

``` nim
proc handshakeExample(peer: Peer) {.async.} =
  ...
  # send a hello message
  peer.hello(...)

  # wait for a matching hello response
  let response = await peer.nextMsg(p2p.hello)
  echo response.clientId # print the name of the Ethereum client
                         # used by the other peer (Geth, Parity, Nimbus, etc)
```

There are few things to note in the above example:

1. The `rlpxProtocol` definition created a pseudo-variable named after the
   protocol holding various properties of the protocol.

2. Each message defined in the protocol received a corresponding type name,
   matching the message name (e.g. `p2p.hello`). This type will have fields
   matching the parameter names of the message. If the messages has `openarray`
   params, these will be remapped to `seq` types.

By default, `nextMsg` will still automatically dispatch all messages different
from the awaited one, but you can prevent this behavior by specifying the extra
flag `discardOthers = true`.

### Checking the other peer's supported sub-protocols

Upon establishing a connection, RLPx will automatically negotiate the list of
mutually supported protocols by the peers. To check whether a particular peer
supports a particular sub-protocol, use the following code:

``` nim
if peer.supports(les): # `les` is the identifier of the light clients sub-protocol
  peer.getReceipts(nextReqId(), neededReceipts())

```

## License

Licensed and distributed under either of
  * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
  * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
at your option. This file may not be copied, modified, or distributed except according to those terms.
