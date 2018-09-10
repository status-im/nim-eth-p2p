#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

## This module implements the Ethereum Wire Protocol:
## https://github.com/ethereum/wiki/wiki/Ethereum-Wire-Protocol

import
  random,
  asyncdispatch2, rlp, stint, eth_common, chronicles,
  ../../eth_p2p

type
  NewBlockHashesAnnounce* = object
    hash: KeccakHash
    number: uint

  NewBlockAnnounce* = object
    header: BlockHeader
    body {.rlpInline.}: BlockBody

  NetworkState = object
    syncing: bool

  PeerState = object
    initialized: bool
    bestBlockHash: KeccakHash
    bestDifficulty: DifficultyInt

const
  maxStateFetch = 384
  maxBodiesFetch = 128
  maxReceiptsFetch = 256
  maxHeadersFetch = 192
  protocolVersion = 63

rlpxProtocol eth, protocolVersion:
  useRequestIds = false

  type State = PeerState

  onPeerConnected do (peer: Peer):
    let
      network = peer.network
      chain = network.chain
      bestBlock = chain.getBestBlockHeader

    await peer.status(protocolVersion,
                      network.networkId,
                      bestBlock.difficulty,
                      bestBlock.blockHash,
                      chain.genesisHash)

    let m = await peer.waitSingleMsg(eth.status)
    peer.state.initialized = true
    peer.state.bestDifficulty = m.totalDifficulty
    peer.state.bestBlockHash = m.bestHash

  proc status(peer: Peer,
              protocolVersion: uint,
              networkId: uint,
              totalDifficulty: DifficultyInt,
              bestHash: KeccakHash,
              genesisHash: KeccakHash) =
    # verify that the peer is on the same chain:
    if peer.network.networkId != networkId or
       peer.network.chain.genesisHash != genesisHash:
      # TODO: Is there a more specific reason here?
      await peer.disconnect(SubprotocolReason)
      return

    peer.state.bestBlockHash = bestHash
    peer.state.bestDifficulty = totalDifficulty

  proc newBlockHashes(peer: Peer, hashes: openarray[NewBlockHashesAnnounce]) =
    discard

  proc transactions(peer: Peer, transactions: openarray[Transaction]) =
    discard

  requestResponse:
    proc getBlockHeaders(peer: Peer, request: BlocksRequest) =
      if request.maxResults > uint64(maxHeadersFetch):
        await peer.disconnect(BreachOfProtocol)
        return

      var headers = newSeqOfCap[BlockHeader](request.maxResults)
      let chain = peer.network.chain
      var foundBlock: BlockHeader

      if chain.getBlockHeader(request.startBlock, foundBlock):
        headers.add foundBlock

        while uint64(headers.len) < request.maxResults:
          if not chain.getSuccessorHeader(foundBlock, foundBlock):
            break
          headers.add foundBlock

      await peer.blockHeaders(headers)

    proc blockHeaders(p: Peer, headers: openarray[BlockHeader])

  requestResponse:
    proc getBlockBodies(peer: Peer, hashes: openarray[KeccakHash]) =
      if hashes.len > maxBodiesFetch:
        await peer.disconnect(BreachOfProtocol)
        return

      var chain = peer.network.chain

      var blockBodies = newSeqOfCap[BlockBody](hashes.len)
      for hash in hashes:
        let blockBody = chain.getBlockBody(hash)
        if not blockBody.isNil:
          # TODO: should there be an else clause here.
          # Is the peer responsible of figuring out that
          # some blocks were not found?
          blockBodies.add deref(blockBody)

      await peer.blockBodies(blockBodies)

    proc blockBodies(peer: Peer, blocks: openarray[BlockBody])

  proc newBlock(peer: Peer, bh: NewBlockAnnounce, totalDifficulty: DifficultyInt) =
    discard

  nextID 13

  requestResponse:
    proc getNodeData(peer: Peer, hashes: openarray[KeccakHash]) =
      await peer.nodeData([])

    proc nodeData(peer: Peer, data: openarray[Blob]) =
      discard

  requestResponse:
    proc getReceipts(peer: Peer, hashes: openarray[KeccakHash]) =
      await peer.receipts([])

    proc receipts(peer: Peer, receipts: openarray[Receipt]) =
      discard

type
  SyncStatus* = enum
    syncSuccess
    syncNotEnoughPeers
    syncTimeOut

  WantedBlocksState = enum
    Initial,
    Requested,
    Received

  WantedBlocks = object
    startIndex: BlockNumber
    numBlocks: uint
    state: WantedBlocksState
    headers: seq[BlockHeader]
    bodies: seq[BlockBody]

  SyncContext = ref object
    workQueue: seq[WantedBlocks]
    endBlockNumber: BlockNumber
    finalizedBlock: BlockNumber # Block which was downloaded and verified
    chain: AbstractChainDB

proc endIndex(b: WantedBlocks): BlockNumber =
  result = b.startIndex
  result += (b.numBlocks - 1).u256

proc availableWorkItem(ctx: SyncContext): int =
  var maxPendingBlock = ctx.finalizedBlock
  result = -1
  for i in 0 .. ctx.workQueue.high:
    case ctx.workQueue[i].state
    of Initial:
      return i
    of Received:
      result = i
    else:
      discard

    let eb = ctx.workQueue[i].endIndex
    if eb > maxPendingBlock: maxPendingBlock = eb

  let nextRequestedBlock = maxPendingBlock + 1
  if nextRequestedBlock >= ctx.endBlockNumber:
    return -1

  if result == -1:
    result = ctx.workQueue.len
    ctx.workQueue.setLen(result + 1)

  var numBlocks = (ctx.endBlockNumber - nextRequestedBlock).toInt
  if numBlocks > maxHeadersFetch:
    numBlocks = maxHeadersFetch
  ctx.workQueue[result] = WantedBlocks(startIndex: nextRequestedBlock, numBlocks: numBlocks.uint, state: Initial)

proc returnWorkItem(ctx: SyncContext, workItem: int) =
  let wi = addr ctx.workQueue[workItem]
  let askedBlocks = wi.numBlocks.int
  let receivedBlocks = wi.headers.len

  if askedBlocks == receivedBlocks:
    debug "Work item complete", startBlock = wi.startIndex,
                                askedBlocks,
                                receivedBlocks
  else:
    warn "Work item complete", startBlock = wi.startIndex,
                                askedBlocks,
                                receivedBlocks

  ctx.chain.persistBlocks(wi.headers, wi.bodies)
  wi.headers.setLen(0)
  wi.bodies.setLen(0)

proc newSyncContext(startBlock, endBlock: BlockNumber, chain: AbstractChainDB): SyncContext =
  new result
  result.endBlockNumber = endBlock
  result.finalizedBlock = startBlock
  result.chain = chain

proc handleLostPeer(ctx: SyncContext) =
  # TODO: ask the PeerPool for new connections and then call
  # `obtainBlocksFromPeer`
  discard

proc randomOtherPeer(node: EthereumNode, particularPeer: Peer): Peer =
  # TODO: we can maintain a per-protocol list of peers in EtheruemNode
  var ethPeersCount = 0
  for peer in node.peers(eth):
    if peer != particularPeer:
      inc ethPeersCount

  if ethPeersCount == 0: return nil
  let peerIdx = random(ethPeersCount) + 1
  for peer in node.peers(eth):
    if peer != particularPeer:
      if peerIdx == ethPeersCount: return peer
      dec ethPeersCount

proc obtainBlocksFromPeer(peer: Peer, syncCtx: SyncContext) {.async.} =
  while (let workItemIdx = syncCtx.availableWorkItem(); workItemIdx != -1):
    template workItem: auto = syncCtx.workQueue[workItemIdx]
    workItem.state = Requested
    debug "Requesting block headers", start = workItem.startIndex, count = workItem.numBlocks
    let request = BlocksRequest(
      startBlock: HashOrNum(isHash: false,
                            number: workItem.startIndex),
      maxResults: workItem.numBlocks,
      skip: 0,
      reverse: false)

    var dataReceived = false
    try:
      let results = await peer.getBlockHeaders(request)
      if results.isSome:
        workItem.state = Received
        shallowCopy(workItem.headers, results.get.headers)

        var bodies = newSeq[BlockBody]()
        var hashes = newSeq[KeccakHash]()
        for i in workItem.headers:
          hashes.add(blockHash(i))
          if hashes.len == maxBodiesFetch:
            let b = await peer.getBlockBodies(hashes)
            hashes.setLen(0)
            bodies.add(b.get.blocks)

        if hashes.len != 0:
          let b = await peer.getBlockBodies(hashes)
          bodies.add(b.get.blocks)

        shallowCopy(workItem.bodies, bodies)
        dataReceived = true
    except:
      # the success case uses `continue`, so we can just fall back to the
      # failure path below. If we signal time-outs with exceptions such
      # failures will be easier to handle.
      discard

    if dataReceived:
      syncCtx.returnWorkItem workItemIdx
    else:
      try:
        await peer.disconnect(SubprotocolReason)
      except:
        discard
      syncCtx.handleLostPeer()
      break

  debug "Nothing to sync"

proc findBestPeer(node: EthereumNode): (Peer, DifficultyInt) =
  var
    bestBlockDifficulty: DifficultyInt = 0.stuint(256)
    bestPeer: Peer = nil

  for peer in node.peers(eth):
    let peerEthState = peer.state(eth)
    if peerEthState.initialized:
      if peerEthState.bestDifficulty > bestBlockDifficulty:
        bestBlockDifficulty = peerEthState.bestDifficulty
        bestPeer = peer

  result = (bestPeer, bestBlockDifficulty)

proc fastBlockchainSync*(node: EthereumNode): Future[SyncStatus] {.async.} =
  ## Code for the fast blockchain sync procedure:
  ## https://github.com/ethereum/wiki/wiki/Parallel-Block-Downloads
  ## https://github.com/ethereum/go-ethereum/pull/1889
  var
    bestBlockNumber: BlockNumber

  debug "start sync"

  var (bestPeer, bestBlockDifficulty) = node.findBestPeer()

  if bestPeer == nil:
    return syncNotEnoughPeers

  while true:
    let request = BlocksRequest(
      startBlock: HashOrNum(isHash: true,
                            hash: bestPeer.state(eth).bestBlockHash),
      maxResults: 1,
      skip: 0,
      reverse: true)

    let latestBlock = await bestPeer.getBlockHeaders(request)

    if latestBlock.isSome and latestBlock.get.headers.len > 0:
      bestBlockNumber = latestBlock.get.headers[0].blockNumber
      break

    # TODO: maintain multiple "best peer" candidates and send requests
    # to the second best option
    bestPeer = node.randomOtherPeer(bestPeer)
    if bestPeer == nil:
      return syncNotEnoughPeers

  # does the network agree with our best block?
  var
    localChain = node.chain
    bestLocalHeader = localChain.getBestBlockHeader

  for peer in node.randomPeers(5):
    if peer.supports(eth):
      let request = BlocksRequest(
        startBlock: HashOrNum(isHash: false,
                              number: bestLocalHeader.blockNumber),
        maxResults: 1,
        skip: 0,
        reverse: true)

      # TODO: check if the majority of peers agree with the block
      # positioned at our best block number.

  # TODO: In case of disagreement, perform a binary search to locate a
  # block where we agree.

  if bestLocalHeader.blockNumber >= bestBlockNumber:
    return syncSuccess

  # 4. Start making requests in parallel for the block headers that we are
  # missing (by requesting blocks from peers while honoring maxHeadersFetch).
  # Make sure the blocks hashes add up. Don't count on everyone replying, ask
  # a different peer in case of time-out. Handle invalid or incomplete replies
  # properly. The peer may respond with fewer headers than requested (or with
  # different ones if the peer is not behaving properly).
  var syncCtx = newSyncContext(bestLocalHeader.blockNumber, bestBlockNumber, node.chain)

  for peer in node.peers:
    if peer.supports(eth):
      # TODO: we should also monitor the PeerPool for new peers here and
      # we should automatically add them to the loop.
      asyncCheck obtainBlocksFromPeer(peer, syncCtx)

  # 5. Store the obtained headers in the blockchain DB

  # 6. Once the sync is complete, repeat from 1. until to further progress is
  # possible

  # 7. Start downloading the blockchain state in parallel
  # (maybe this could start earlier).

