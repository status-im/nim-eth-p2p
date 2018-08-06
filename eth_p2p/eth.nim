#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import asyncdispatch2, stint, rlp, eth_common, chronicles
import protocols, peer

const
  # Max number of items we can ask for in ETH requests. These are the values
  # used in geth and if we ask for more than this the peers will disconnect
  # from us.
  MaxStateFetch* = 384
  MaxBodiesFetch* = 128
  MaxReceiptsFetch* = 256
  MaxHeadersFetch* = 192

const
  MsgStatus* = 0x00
  MsgNewBlockHashes* = 0x01
  MsgTransactions* = 0x02
  # eth/61
  MsgGetBlockHashes* = 0x03
  MsgBlockHashes* = 0x04
  MsgGetBlocks* = 0x05
  MsgBlocks* = 0x06
  MsgNewBlock* = 0x07
  MsgBlockHashesFromNumber* = 0x08
  # eth/62
  MsgGetBlockHeaders* = 0x03
  MsgBlockHeaders* = 0x04
  MsgGetBlockBodies* = 0x05
  MsgBlockBodies* = 0x06
  # eth/63
  MsgGetNodeData* = 0x0D
  MsgNodeData* = 0x0E
  MsgGetReceipts* = 0x0F
  MsgReceipts* = 0x10



const
  EthereumCap61* = initECap("eth", 61)
  EthereumCap62* = initECap("eth", 62)
  EthereumCap63* = initECap("eth", 63)

proc ethGetCmd*(epcap: EPeerCap, cmd: int): int =
  ## Checks if specific message is supported by capability/protocol ``epcap``
  ## and returns (zero based) specific to protocol message id.
  ## If `cmd` identifier is not supported by specific protocol ``epcap`` -1 will
  ## be returned.
  result = -1
  let cmdId = epcap.protoId(cmd)
  if epcap.cap == EthereumCap61:
    if cmdId in {MsgStatus, MsgNewBlockHashes, MsgTransactions,
                 MsgGetBlockHashes, MsgBlockHashes, MsgGetBlocks,
                 MsgBlocks, MsgNewBlock, MsgBlockHashesFromNumber}:
      result = cmdId
  elif epcap.cap == EthereumCap62:
    if cmdId in {MsgStatus, MsgNewBlockHashes, MsgTransactions,
                 MsgGetBlockHeaders, MsgBlockHeaders, MsgGetBlockBodies,
                 MsgBlockBodies, MsgNewBlock}:
      result = cmdId
  elif epcap.cap == EthereumCap63:
    if cmdId in {MsgStatus, MsgNewBlockHashes, MsgTransactions,
                 MsgGetBlockHeaders, MsgBlockHeaders, MsgGetBlockBodies,
                 MsgBlockBodies, MsgNewBlock, MsgGetNodeData, MsgNodeData,
                 MsgGetReceipts, MsgReceipts}:
      result = cmdId
  else:
    discard

proc sendStatus*(peer: Peer, cap: EPeerCap, networkId: int,
                 tdifficulty: UInt256, bestHash: Hash256,
                 genesisHash: Hash256): Future[bool] {.async.} =
  ## Send `Status` message to remote peer
  if peer.state notin {ConnectionState.None, Connected}: return false

  let eindex = peer.supports([EthereumCap61, EthereumCap62, EthereumCap63])
  doAssert(eindex >= 0, "Peer do not support eth status()")
  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgStatus)
  writer.append(int(cmdId))
  writer.startList(5)
  writer.append(int(cap.version))
  writer.append(int(networkId))
  writer.append(tdifficulty)
  writer.append(bestHash)
  writer.append(genesisHash)
  debug "Sending Status message", peer = $peer, version = $cap.version
  result = await peer.sendMessage(writer.finish())

proc sendNewBlockHashes*(peer: Peer,
                         hashes: seq[Hash256]): Future[bool] {.async.} =
  if peer.state != Connected: return false

  let eindex = peer.supports(EthereumCap61)
  doAssert(eindex >= 0, "Peer do not support NewBlockHashes()")
  let cap = peer.caps[eindex]
  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgNewBlockHashes)
  writer.append(int(cmdId))
  writer.startList(len(hashes))
  for hash in hashes:
    writer.append(hash)
  debug "Sending NewBlockHashes message", peer = $peer, version = $cap.version
  result = await peer.sendMessage(writer.finish())

proc sendNewBlockHashes*(peer: Peer,
     bhashes: seq[tuple[hash: Hash256, num: UInt256]]): Future[bool] {.async.} =
  if peer.state != Connected: return false

  let eindex = peer.supports(EthereumCap62)
  doAssert(eindex >= 0, "Peer do not support NewBlockHashes()")
  let cap = peer.caps[eindex]
  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgNewBlockHashes)
  writer.append(int(cmdId))
  writer.startList(len(bhashes))
  for item in bhashes:
    writer.startList(2)
    writer.append(item.hash)
    writer.append(item.num)
  debug "Sending NewBlockHashes message", peer = $peer, version = $cap.version
  result = await peer.sendMessage(writer.finish())

proc sendBlockHashes*(peer: Peer,
                      hashes: seq[Hash256]): Future[bool] {.async.} =
  if peer.state != Connected: return false

  let eindex = peer.supports(EthereumCap61)
  doAssert(eindex >= 0, "Peer do not support NewBlockHashes()")
  let cap = peer.caps[eindex]
  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgBlockHashes)
  writer.append(int(cmdId))
  writer.startList(len(hashes))
  for hash in hashes:
    writer.append(hash)
  debug "Sending BlockHashes message", peer = $peer, version = $cap.version
  result = await peer.sendMessage(writer.finish())

# Missing 0x01:sendNewBlockHashes eth/61
# Missing 0x02:sendTransactions eth/61
# Missing 0x06:sendBlocks eth/61
# Missing 0x07:newBlock eth/61

# Missing 0x04:sendBlockHeaders eth/62
# Missing 0x06:sendBlockBodies eth/62

# Missing 0x0E:sendNodeDat eth/63
# Missing 0x10:sendReceipts eth/63

template sendReceive(peer: Peer, epcap: EPeerCap, sendMsg: BytesRange,
                     msgId: int, name: string): EthereumMessage =
  let startTime = fastEpochTime()
  var msg = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  var sendfut = peer.sendMessage(sendMsg)
  yield sendfut
  let res = sendfut.read()
  if res:
    var fut = newFuture[EthereumMessage](name)
    peer.subscribe(epcap, msgId, fut)
    try:
      var msgfut = wait(fut, peer.responseTimeout)
      yield msgfut
      msg = msgfut.read()
      msg.elapsed = int(fastEpochTime() - startTime)
      peer.unsubscribe(epcap, msgId)
    except AsyncTimeoutError:
      msg = EthereumMessage(id: MsgTimeout, data: zeroBytesRlp)
  msg

proc getBlockHashesFromNumber*(peer: Peer, number: UInt256,
                            maxBlocks: int): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap61)
  doAssert(eindex >= 0, "Peer do not support getblockHashesFromNumber()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgBlockHashesFromNumber)
  writer.append(int(cmdId))
  writer.startList(2)
  writer.append(number)
  writer.append(maxBlocks)
  debug "Sending BlockHashesFromNumber message", peer = $peer,
                                                 version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgBlockHashes,
                            "eth.getBlockHashesFromNumber")

proc getBlockHashes*(peer: Peer, hash: Hash256,
                     maxBlocks: int): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap61)
  doAssert(eindex >= 0, "Peer do not support getBlockHashes()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgGetBlockHashes)
  writer.append(int(cmdId))
  writer.startList(2)
  writer.append(hash)
  writer.append(maxBlocks)
  debug "Sending GetBlockHashes message", peer = $peer, version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgBlockHashes,
                            "eth.getBlockHashes")

proc getBlocks*(peer: Peer,
                hashes: seq[Hash256]): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap61)
  doAssert(eindex >= 0, "Peer do not support getBlocks()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgBlocks)
  writer.append(int(cmdId))
  writer.startList(len(hashes))
  for item in hashes:
    writer.append(item)
  debug "Sending GetBlocks message", peer = $peer, version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgBlocks, "eth.getBlocks")

proc getBlockHeaders*(peer: Peer, blok: UInt256, maxHeaders: int, skip: int,
                      reverse: bool): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap62)
  doAssert(eindex >= 0, "Peer do not support getBlockHeaders()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgGetBlockHeaders)
  writer.append(int(cmdId))
  writer.startList(4)
  writer.append(blok)
  writer.append(maxHeaders)
  writer.append(skip)
  if reverse:
    writer.append(int(1))
  else:
    writer.append(int(0))
  debug "Sending GetBlockHeaders message", peer = $peer, version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgBlockHeaders,
                            "eth.getBlockHeaders")

proc getBlockHeaders*(peer: Peer, blok: Hash256, maxHeaders: int, skip: int,
                      reverse: bool): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap62)
  doAssert(eindex >= 0, "Peer do not support getBlockHeaders()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgGetBlockHeaders)
  writer.append(int(cmdId))
  writer.startList(4)
  writer.append(blok)
  writer.append(maxHeaders)
  writer.append(skip)
  if reverse:
    writer.append(int(1))
  else:
    writer.append(int(0))
  debug "Sending GetBlockHeaders message", peer = $peer, version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgBlockHeaders,
                            "eth.getBlockHeaders")

proc getBlockBodies*(peer: Peer,
                     hashes: seq[Hash256]): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap62)
  doAssert(eindex >= 0, "Peer do not support getBlockBodies()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgGetBlockHeaders)
  writer.append(int(cmdId))
  writer.startList(len(hashes))
  for item in hashes:
    writer.append(item)
  debug "Sending GetBlockBodies message", peer = $peer, version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgBlockBodies,
                            "eth.getBlockBodies")

proc getNodeData*(peer: Peer,
                  hashes: seq[Hash256]): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap63)
  doAssert(eindex >= 0, "Peer do not support getNodeData()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgGetNodeData)
  writer.append(int(cmdId))
  writer.startList(len(hashes))
  for item in hashes:
    writer.append(item)
  debug "Sending GetNodeData message", peer = $peer, version = $cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgNodeData,
                            "eth.getNodeData")

proc getReceipts*(peer: Peer,
                  hashes: seq[Hash256]): Future[EthereumMessage] {.async.} =
  result = EthereumMessage(id: MsgBad, data: zeroBytesRlp)
  if peer.state != Connected: return

  let eindex = peer.supports(EthereumCap63)
  doAssert(eindex >= 0, "Peer do not support getReceipts()")
  let cap = peer.caps[eindex]

  var writer = initRlpWriter()
  let cmdId = cap.cmdId(MsgGetNodeData)
  writer.append(int(cmdId))
  writer.startList(len(hashes))
  for item in hashes:
    writer.append(item)
  debug "Sending GetReceipts message", peer = $peer,
                                       version = $cap.cap.version

  result = peer.sendReceive(cap, writer.finish(), MsgReceipts,
                            "eth.getReceipts")
