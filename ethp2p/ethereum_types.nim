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
  rlp/types, nimcrypto/hash, ttmath

export
  MDigest

type
  # XXX: Some of the UInt256 fields may be unnecessarily large

  P* = UInt256

  KeccakHash* = MDigest[256]
  KeyValuePair* = (BytesRange, BytesRange)

  BlockNonce* = UInt256
  Blob* = seq[byte]

  BloomFilter* = distinct KeccakHash
  EthAddress* = distinct MDigest[160]

  Transaction* = object
    accountNonce*:  uint64
    gasPrice*:      UInt256
    gasLimit*:      uint64
    to*:            EthAddress
    value*:         UInt256
    payload*:       Blob
    V*, R*, S*:     UInt256

  AccessList* = object
    # XXX: Specify the structure of this

  BlockHeader* = object
    parentHash*:    KeccakHash
    uncleHash*:     KeccakHash
    coinbase*:      EthAddress
    stateRoot*:     KeccakHash
    txRoot*:        KeccakHash
    receiptRoot*:   KeccakHash
    bloom*:         BloomFilter
    difficulty*:    UInt256
    blockNumber*:   uint
    gasLimit*:      uint64
    gasUsed*:       uint64
    timestamp*:     uint64
    extraData*:     Blob
    mixDigest*:     KeccakHash
    nonce*:         BlockNonce

  BlockBody* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[BlockHeader]

  Log* = object
    address*:       EthAddress
    topics*:        seq[int32]
    data*:          Blob

  Receipt* = object
    stateRoot*:     Blob
    gasUsed*:       uint64
    bloom*:         BloomFilter
    logs*:          seq[Log]

  ShardTransaction* = object
    chain*:         uint
    shard*:         uint
    to*:            EthAddress
    data*:          Blob
    gas*:           uint64
    acceesList*:    AccessList
    code*:          Blob
    salt*:          KeccakHash

  CollationHeader* = object
    shard*:         uint
    expectedPeriod*: uint
    periodStartPrevHash*: KeccakHash
    parentHash*:    KeccakHash
    txRoot*:        KeccakHash
    coinbase*:      EthAddress
    stateRoot*:     KeccakHash
    receiptRoot*:   KeccakHash
    blockNumber*:   uint

  HashOrNum* = object
    case isHash*: bool
    of true:
      hash*: KeccakHash
    else:
      number*: uint

  BlocksRequest* = object
    startBlock*: HashOrNum
    maxResults*, skip*, reverse*: uint
