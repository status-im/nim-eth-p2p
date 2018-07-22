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
  times,
  asyncdispatch2, rlp, eth_common/eth_types,
  ../../eth_p2p

type
  ProofRequest* = object
    blockHash*: KeccakHash
    accountKey*: Blob
    key*: Blob
    fromLevel*: uint

  HeaderProofRequest* = object
    chtNumber*: uint
    blockNumber*: uint
    fromLevel*: uint

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

  PeerState = object
    buffer: int
    lastRequestTime: float
    reportedTotalDifficulty: Difficulty

  KeyValuePair = object
    key: string
    value: Blob

const
  maxHeadersFetch = 192
  maxBodiesFetch = 32
  maxReceiptsFetch = 128
  maxCodeFetch = 64
  maxProofsFetch = 64
  maxHeaderProofsFetch = 64

# Handshake properties:
# https://github.com/zsfelfoldi/go-ethereum/wiki/Light-Ethereum-Subprotocol-(LES)
const
  keyProtocolVersion = "protocolVersion"
    ## P: is 1 for the LPV1 protocol version.

  keyNetworkId = "networkId"
    ## P: should be 0 for testnet, 1 for mainnet.

  keyHeadTotalDifficulty = "headTd"
    ## P: Total Difficulty of the best chain.
    ## Integer, as found in block header.

  keyHeadHash = "headHash"
    ## B_32: the hash of the best (i.e. highest TD) known block.

  keyHeadNumber = "headNum"
    ## P: the number of the best (i.e. highest TD) known block.

  keyGenesisHash = "genesisHash"
    ## B_32: the hash of the Genesis block.

  keyServeHeaders = "serveHeaders"
    ## (optional, no value)
    ## present if the peer can serve header chain downloads.

  keyServeChainSince = "serveChainSince"
    ## P (optional)
    ## present if the peer can serve Body/Receipts ODR requests
    ## starting from the given block number.

  keyServeStateSince = "serveStateSince"
    ## P (optional):
    ## present if the peer can serve Proof/Code ODR requests
    ## starting from the given block number.

  keyRelaysTransactions = "txRelay"
    ## (optional, no value)
    ## present if the peer can relay transactions to the ETH network.

  keyFlowControlBL = "flowControl/BL"
  keyFlowControlMRC = "flowControl/MRC"
  keyFlowControlMRR = "flowControl/MRR"
    ## see Client Side Flow Control:
    ## https://github.com/zsfelfoldi/go-ethereum/wiki/Client-Side-Flow-Control-model-for-the-LES-protocol

const
  rechargeRate = 0.3

proc getPeerWithNewestChain(pool: PeerPool): Peer =
  discard

rlpxProtocol les, 2:

  type State = PeerState

  ## Handshake
  ##

  proc status(p: Peer, values: openarray[KeyValuePair]) =
    discard

  ## Header synchronisation
  ##

  proc announce(p: Peer,
                headHash: KeccakHash,
                headNumber: BlockNumber,
                headTotalDifficulty: Difficulty,
                reorgDepth: BlockNumber,
                values: openarray[KeyValuePair],
                announceType: uint) =
    discard

  requestResponse:
    proc getBlockHeaders(p: Peer, BV: uint, req: BlocksRequest) =
      discard

    proc blockHeaders(p: Peer, BV: uint, blocks: openarray[BlockHeader]) =
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
    proc getHeaderProofs(p: Peer, requests: openarray[ProofRequest]) =
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

