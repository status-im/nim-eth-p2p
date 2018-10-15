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
  random, algorithm, hashes,
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
  minPeersToStartSync = 2 # Wait for consensus of at least this number of peers before syncing

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
    if m.networkId == network.networkId and m.genesisHash == chain.genesisHash:
      debug "Suitable peer", peer
    else:
      raise newException(UselessPeerError, "Eth handshake params mismatch")
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

proc hash*(p: Peer): Hash {.inline.} = hash(cast[pointer](p))


