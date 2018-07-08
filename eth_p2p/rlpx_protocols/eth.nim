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
  rlp/types, stint, rlpx, eth_common

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
    reportedTotalDifficulty: Difficulty
    latestBlockHash: KeccakHash

const
  maxStateFetch = 384
  maxBodiesFetch = 128
  maxReceiptsFetch = 256
  maxHeadersFetch = 192

rlpxProtocol eth, 63:
  useRequestIds = false

  proc status(peer: Peer,
              protocolVersion, networkId: uint,
              totalDifficulty: Difficulty,
              bestHash, genesisHash: KeccakHash) =
    # verify that the peer is on the same chain:
    if peer.network.id != networkId or
       peer.network.chain.genesisHash != genesisHash:
      peer.disconnect()
      return

    p.state.reportedTotalDifficulty = totalDifficulty

  proc newBlockHashes(peer: Peer, hashes: openarray[NewBlockHashesAnnounce]) =
    discard

  proc transactions(p: Peer, transactions: openarray[Transaction]) =
    discard

  requestResponse:
    proc getBlockHeaders(peer: Peer, request: BlocksRequest) =
      if request.maxResults > maxHeadersFetch:
        peer.disconnect()
        return

      var foundBlock = peer.network.chain.locateBlock(startBlock)
      if not foundBlock.isNil:
        var headers = newSeqOfCap[BlockHeader](request.maxResults)

        while headers.len < request.maxResults:
          headers.add peer.network.chain.getBlockHeader(foundBlock)
          foundBlock = foundBlock.nextBlock()
          if foundBlock.isNil: break

        discard await peer.blockHeaders(headers)

    proc blockHeaders(p: Peer, headers: openarray[BlockHeader])

  requestResponse:
    proc getBlockBodies(p: Peer, hashes: openarray[KeccakHash]) =
      if hashes.len > maxBodiesFetch:
        peer.disconnect()
        return

      var blockBodies = newSeqOfCap[BlockBody](hashes.len)
      for hash in hashes:
        let blockBody = peer.network.chain.getBlockBody(hash)
        if not blockBody.isNil:
          blockBodies.add deref(blockBody)

      discard await peer.blockBodies(blockBodies)

    proc blockBodies(p: Peer, blocks: openarray[BlockBody])

  proc newBlock(p: Peer, bh: NewBlockAnnounce, totalDifficulty: Difficulty) =
    discard

  nextID 13

  requestResponse:
    proc getNodeData(p: Peer, hashes: openarray[KeccakHash]) =
      discard

    proc nodeData(p: Peer, data: openarray[Blob]) =
      discard

  requestResponse:
    proc getReceipts(p: Peer, hashes: openarray[KeccakHash]) =
      discard

    proc receipts(p: Peer, receipts: openarray[Receipt]) =
      discard

proc fastBlockchainSync*(network: EthereumNode) {.async.} =
  # 1. obtain last N block headers from all peers
  var latestBlocksRequest: BlocksRequest
  var requests = newSeqOfCap[Future[eth.blockHeaders]](32)
  for peer in network.peerPool:
    if peer.supports(eth):
      requests.add peer.getBlockHeaders(latestBlocksRequest)

  await all(requests)

  # 2. find out what is the block with best total difficulty
  var bestBlockDifficulty: Difficulty = 0
  for req in requests:
    if req.read.isNone: continue
    for header in req.read.get.headers:
      if header.difficulty > bestBlockDifficulty:
        discard

  # 3. establish the highest valid block for each peer
  # keep in mind that some of the peers may report an alternative history, so
  # we must find the last block where each peer agreed with the best peer

  # 4. Start making requests in parallel for the block headers that we are
  # missing (by requesting blocks from peers while honoring maxHeadersFetch).
  # Make sure the blocks hashes add up. Don't count on everyone replying, ask
  # a different peer in case of time-out. Handle invalid or incomplete replies
  # properly. The peer may response with fewer headers than requested (or with
  # different ones if the peer is not behaving properly).

  # 5. Store the obtained headers in the blockchain DB

  # 6. Once the sync is complete, repeat from 1. until to further progress is
  # possible

  # 7. Start downloading the blockchain state in parallel
  # (maybe this could start earlier).

