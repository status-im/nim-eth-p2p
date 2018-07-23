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
  random,
  asyncdispatch2, rlp, stint, eth_common,
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
                      deref(bestBlock).difficulty,
                      deref(bestBlock).blockHash,
                      chain.genesisHash)

    discard await peer.nextMsg(eth.status)
    peer.state.initialized = true

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

      var chain = peer.network.chain

      var foundBlock = chain.getBlockHeader(request.startBlock)
      if not foundBlock.isNil:
        var headers = newSeqOfCap[BlockHeader](request.maxResults)

        while uint64(headers.len) < request.maxResults:
          headers.add deref(foundBlock)
          foundBlock = chain.getSuccessorHeader deref(foundBlock)
          if foundBlock.isNil: break

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
      discard

    proc nodeData(peer: Peer, data: openarray[Blob]) =
      discard

  requestResponse:
    proc getReceipts(peer: Peer, hashes: openarray[KeccakHash]) =
      discard

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
    startIndex, endIndex: int
    results: seq[BlockHeader]
    state: WantedBlocksState
    nextWorkItem: int

  SyncContext = ref object
    workQueue: seq[WantedBlocks]
    nextWorkItem: int

proc popWorkItem(ctx: SyncContext): int =
  result = ctx.nextWorkItem
  ctx.nextWorkItem = ctx.workQueue[result].nextWorkItem

proc returnWorkItem(ctx: SyncContext, workItem: int) =
  ctx.workQueue[workItem].state = Initial
  ctx.workQueue[workItem].nextWorkItem = ctx.nextWorkItem
  ctx.nextWorkItem = workItem

proc newSyncContext(startBlock, endBlock: int): SyncContext =
  new result

  let totalBlocksNeeded = endBlock - startBlock
  let workQueueSize = totalBlocksNeeded div maxHeadersFetch
  result.workQueue = newSeq[WantedBlocks](workQueueSize)

  for i in 0 ..< workQueueSize:
    let startIndex = startBlock + i * maxHeadersFetch
    result.workQueue[i].startIndex = startIndex
    result.workQueue[i].endIndex = startIndex + maxHeadersFetch
    result.nextWorkItem = i + 1

  if totalBlocksNeeded mod maxHeadersFetch == 0:
    result.workQueue[^1].nextWorkItem = -1
  else:
    # TODO: this still has a tiny risk of reallocation
    result.workQueue.add WantedBlocks(
      startIndex: result.workQueue[^1].endIndex + 1,
      endIndex: endBlock,
      nextWorkItem: -1)

proc handleLostPeer(ctx: SyncContext) =
  # TODO: ask the PeerPool for new connections and then call
  # `obtainsBlocksFromPeer`
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

proc obtainsBlocksFromPeer(peer: Peer, syncCtx: SyncContext) {.async.} =
  # TODO: add support for request pipelining here
  # (asking for multiple blocks even before the results are in)

  while (let workItemIdx = syncCtx.popWorkItem; workItemIdx != -1):
    template workItem: auto = syncCtx.workQueue[workItemIdx]

    workItem.state = Requested

    let request = BlocksRequest(
      startBlock: HashOrNum(isHash: false,
                            number: workItem.startIndex.toBlockNumber),
      maxResults: maxHeadersFetch,
      skip: 0,
      reverse: false)

    try:
      let results = await peer.getBlockHeaders(request)
      if results.isSome:
        workItem.state = Received
        shallowCopy(workItem.results, results.get.headers)
        continue
    except:
      # the success case uses `continue`, so we can just fall back to the
      # failure path below. If we signal time-outs with exceptions such
      # failures will be easier to handle.
      discard

    # This peer proved to be unreliable. TODO: Decrease its reputation.
    await peer.disconnect(SubprotocolReason)
    syncCtx.returnWorkItem workItemIdx
    syncCtx.handleLostPeer()

proc fastBlockchainSync*(node: EthereumNode): Future[SyncStatus] {.async.} =
  var
    bestBlockDifficulty: DifficultyInt = 0.stuint(256)
    bestPeer: Peer = nil
    bestBlockNumber: BlockNumber

  for peer in node.peers(eth):
    let peerEthState = peer.state(eth)
    if peerEthState.initialized:
      if peerEthState.bestDifficulty > bestBlockDifficulty:
        bestBlockDifficulty = peerEthState.bestDifficulty
        bestPeer = peer

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
  var syncCtx = newSyncContext(bestLocalHeader.blockNumber.toInt,
                               bestBlockNumber.toInt)

  for peer in node.peers:
    if peer.supports(eth):
      # TODO: we should also monitor the PeerPool for new peers here and
      # we should automatically add them to the loop.
      asyncCheck obtainsBlocksFromPeer(peer, syncCtx)

  # 5. Store the obtained headers in the blockchain DB

  # 6. Once the sync is complete, repeat from 1. until to further progress is
  # possible

  # 7. Start downloading the blockchain state in parallel
  # (maybe this could start earlier).

