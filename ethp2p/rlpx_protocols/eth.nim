import
  rlp/types, ttmath, rlpx, ethereum_types

type
  P = UInt256

  NewBlockHashesAnnounce* = object
    hash: KeccakHash
    number: uint

  NewBlockAnnounce* = object
    header: BlockHeader
    body {.rlpInline.}: BlockBody

rlpxProtocol("eth", 63):
  proc status(p: Peer, protocolVersion, networkId, td: P,
              bestHash, genesisHash: KeccakHash) =
    discard

  proc newBlockHashes(p: Peer, hashes: openarray[NewBlockHashesAnnounce]) =
    discard

  proc transactions(p: Peer, transactions: openarray[Transaction]) =
    discard

  proc getBlockHeaders(p: Peer, hash: BlocksRequest) =
    discard

  proc blockHeaders(p: Peer, hashes: openarray[BlockHeader]) =
    discard

  proc getBlockBodies(p: Peer, hashes: openarray[KeccakHash]) =
    discard

  proc blockBodies(p: Peer, blocks: openarray[BlockBody]) =
    discard

  proc newBlock(p: Peer, bh: NewBlockAnnounce, totalDificulty: P) =
    discard

  nextID 13

  proc getNodeData(p: Peer, hashes: openarray[KeccakHash]) =
    discard

  proc nodeData(p: Peer, data: openarray[Blob]) =
    discard

  proc getReceipts(p: Peer, hashes: openarray[KeccakHash]) =
    discard

  proc receipts(p: Peer, receipts: openarray[Receipt]) =
    discard

