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

  requestResponse:
    proc getBlockHeaders(p: Peer, BV: uint, req: BlocksRequest) =
      discard

    proc blockHeaders(p: Peer, BV: uint, blocks: openarray[BlockHeaders]) =
      discard

  ## On-damand data retrieval
  ##

  requestResponse:
    proc getBlockBodies(p: Peer, blocks: openarray[KeccakHash]) =
      discard

    proc blockBodies(p: Peer, BV: uint, bodies: openarray[BlockBody]) =
      discard

  requestResponse:
    proc getReceipts(p: Peer, hashes: openarray[KeccakHash]) =
      discard

    proc receipts(p: Peer, BV: uint, receipts: openarray[Receipt]) =
      discard

  requestResponse:
    proc getProofs(p: Peer, proofs: openarray[ProofRequest]) =
      discard

    proc proofs(p: Peer, BV: uint, proofs: openarray[Blob]) =
      discard

  requestResponse:
    proc getContractCodes(p: Peer, requests: seq[ContractCodeRequest]) =
      discard

    proc contractCodes(p: Peer, BV: uint, results: seq[Blob]) =
      discard

  nextID 15

  requestResponse:
    proc getHeaderProofs(p: Peer, requests: openarray[HeaderProofRequest]) =
      discard

    proc headerProof(p: Peer, BV: uint, proofs: openarray[Blob]) =
      discard

  requestResponse:
    proc getHelperTrieProofs(p: Peer, requests: openarray[HelperTrieProofRequest]) =
      discard

    proc helperTrieProof(p: Peer, BV: uint, nodes: seq[Blob], auxData: seq[Blob]) =
      discard

  ## Transaction relaying and status retrieval
  ##

  requestResponse:
    proc sendTxV2(p: Peer, transactions: openarray[Transaction]) =
      discard

    proc getTxStatus(p: Peer, transactions: openarray[Transaction]) =
      discard

    proc txStatus(p: Peer, BV: uint, transactions: openarray[TransactionStatusMsg]) =
      discard

