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
  rlp/types, rlpx, ethereum_types

type
  ProofRequest* = object
    blockHash*: KeccakHash
    accountKey*: Blob
    key*: Blob
    fromLevel*: UInt256

  ContractCodeRequest* = object
    blockHash*: KeccakHash
    key*: EthAddress

  HelperTrieProofRequest* = object
    subType*: uint
    sectionIdx*: uint
    key*: Blob
    fromLevel*: uint
    auxReq*: uint

  TransactionStatus* = enum
    Unknown,
    Queued,
    Pending,
    Included,
    Error

  TransactionStatusMsg* = object
    status*: TransactionStatus
    data*: Blob

rlpxProtocol les, 2:

  ## Handshake
  ##

  proc status(p: Peer, values: openarray[KeyValuePair]) =
    discard

  ## Header synchronisation
  ##

  proc announce(p: Peer, headHash: KeccakHash,
                headNumber, headTd, reorgDepth: P,
                values: openarray[KeyValuePair], announceType: uint) =
    discard

  proc getBlockHeaders(p: Peer, reqID, BV: uint, req: BlocksRequest) =
    discard

  proc blockHeaders(p: Peer, reqID, BV: uint, blocks: openarray[BlockHeaders]) =
    discard

  ## On-damand data retrieval
  ##

  proc getBlockBodies(p: Peer, reqID: uint, blocks: openarray[KeccakHash]) =
    discard

  proc blockBodies(p: Peer, reqID, BV: uint, bodies: openarray[BlockBody]) =
    discard

  proc getReceipts(p: Peer, reqID: uint, hashes: openarray[KeccakHash]) =
    discard

  proc receipts(p: Peer, reqID, BV: uint, receipts: openarray[Receipt]) =
    discard

  proc getProofs(p: Peer, reqID: uint, proofs: openarray[ProofRequest]) =
    discard

  proc proofs(p: Peer, reqID, BV: uint, proofs: openarray[Blob]) =
    discard

  proc getContractCodes(p: Peer, reqID: uint, requests: seq[ContractCodeRequest]) =
    discard

  proc contractCodes(p: Peer, reqID, BV: uint, results: seq[Blob]) =
    discard

  nextID 15

  proc getHeaderProofs(p: Peer, reqID: uint, requests: openarray[HeaderProofRequest]) =
    discard

  proc headerProof(p: Peer, reqID, BV: uint, proofs: openarray[Blob]) =
    discard

  proc getHelperTrieProofs(p: Peer, reqId: uint, requests: openarray[HelperTrieProofRequest]) =
    discard

  proc helperTrieProof(p: Peer, reqId, BV: uint, nodes: seq[Blob], auxData: seq[Blob]) =
    discard

  ## Transaction relaying and status retrieval
  ##

  proc sendTxV2(p: Peer, reqId: uint, transactions: openarray[Transaction]) =
    discard

  proc getTxStatus(p: Peer, reqId: uint, transactions: openarray[Transaction]) =
    discard

  proc txStatus(p: Peer, reqId, BV: uint, transactions: openarray[TransactionStatusMsg]) =
    discard

