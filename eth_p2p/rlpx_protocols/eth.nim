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
    reportedTotalDifficulty: DifficultyInt
    latestBlockHash: KeccakHash

const
  maxStateFetch = 384
  maxBodiesFetch = 128
  maxReceiptsFetch = 256
  maxHeadersFetch = 192

rlpxProtocol eth, 63:
  useRequestIds = false

  type State = PeerState

  proc status(peer: Peer,
              protocolVersion, networkId: uint,
              totalDifficulty: DifficultyInt,
              bestHash, genesisHash: KeccakHash) =
    # verify that the peer is on the same chain:
    if peer.network.networkId != networkId or
       peer.network.chain.genesisHash != genesisHash:
      # TODO: Is there a more specific reason here?
      await peer.disconnect(SubprotocolReason)
      return

    peer.state.reportedTotalDifficulty = totalDifficulty

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

proc fastBlockchainSync*(node: EthereumNode) {.async.} =
  # 1. obtain last N block headers from all peers
  var latestBlocksRequest: BlocksRequest
  var requests = newSeqOfCap[Future[Option[eth.blockHeaders]]](32)
  for peer in node.peers:
    if peer.supports(eth):
      requests.add peer.getBlockHeaders(latestBlocksRequest)

  discard await all(requests)

  # 2. find out what is the block with best total difficulty
  var bestBlockDifficulty: DifficultyInt = 0.stuint(256)
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
  # properly. The peer may respond with fewer headers than requested (or with
  # different ones if the peer is not behaving properly).

  # 5. Store the obtained headers in the blockchain DB

  # 6. Once the sync is complete, repeat from 1. until to further progress is
  # possible

  # 7. Start downloading the blockchain state in parallel
  # (maybe this could start earlier).

