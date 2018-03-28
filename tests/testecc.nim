#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

import unittest
import ethp2p/ecc
import nimcrypto/hash, nimcrypto/keccak, nimcrypto/utils

proc compare(x: openarray[byte], y: openarray[byte]): bool =
  result = len(x) == len(y)
  if result:
    for i in 0..(len(x) - 1):
      if x[i] != y[i]:
        result = false
        break

suite "ECC/ECDSA/ECDHE tests suite":
  test "ECDHE/py-evm test_ecies.py#L19":
    # ECDHE test vectors
    # Copied from
    # https://github.com/ethereum/py-evm/blob/master/tests/p2p/test_ecies.py#L19
    const privateKeys = [
      "332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b",
      "7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad"
    ]
    const publicKeys = [
      """f0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a07
         f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1""",
      """83ede0f19c3c98649265956a4193677b14c338a22de2086a08d84e4446fe37e4e
         233478259ec90dbeef52f4f6c890f8c38660ec7b61b9d439b8a6d1c323dc025"""
    ]
    const sharedSecrets = [
      "ee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08",
      "167ccc13ac5e8a26b131c3446030c60fbfac6aa8e31149d0869f93626a4cdf62"
    ]
    var secret: array[KeyLength, byte]
    for i in 0..1:
      var s = privateKeys[i].getPrivateKey()
      var p = publicKeys[i].getPublicKey()
      let expect = fromHex(stripSpaces(sharedSecrets[i]))
      check:
        ecdhAgree(s, p, secret) == Success
        compare(expect, secret) == true

  test "ECDHE/cpp-ethereum crypto.cpp#L394":
    # ECDHE test vectors
    # Copied from https://github.com/ethereum/cpp-ethereum/blob/develop/test/unittests/libdevcrypto/crypto.cpp#L394
    var expectm = """
      8ac7e464348b85d9fdfc0a81f2fdc0bbbb8ee5fb3840de6ed60ad9372e718977"""
    var secret: array[KeyLength, byte]
    var s = keccak256.digest("ecdhAgree").data
    var p = s.getPublicKey()
    let expect = fromHex(stripSpaces(expectm))
    check:
      ecdhAgree(s, p, secret) == Success
      compare(expect, secret) == true

  test "ECDHE/cpp-ethereum rlpx.cpp#L425":
    # ECDHE test vectors
    # Copied from https://github.com/ethereum/cpp-ethereum/blob/2409d7ec7d34d5ff5770463b87eb87f758e621fe/test/unittests/libp2p/rlpx.cpp#L425
    var s0 = """
      332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b"""
    var p0 = """
      f0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a0
      7f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1"""
    var e0 = """
      ee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08"""
    var secret: array[KeyLength, byte]
    var s = getPrivateKey(s0)
    var p = getPublicKey(p0)
    let expect = fromHex(stripSpaces(e0))
    check:
      ecdhAgree(s, p, secret) == Success
      compare(expect, secret) == true

  test "ECDSA/cpp-ethereum crypto.cpp#L132":
    # ECDSA test vectors
    # Copied from https://github.com/ethereum/cpp-ethereum/blob/develop/test/unittests/libdevcrypto/crypto.cpp#L132
    var signature = """
      b826808a8c41e00b7c5d71f211f005a84a7b97949d5e765831e1da4e34c9b8295d
      2a622eee50f25af78241c1cb7cfff11bcf2a13fe65dee1e3b86fd79a4e3ed000"""
    var pubkey = """
      e40930c838d6cca526795596e368d16083f0672f4ab61788277abfa23c3740e1cc
      84453b0b24f49086feba0bd978bb4446bae8dff1e79fcc1e9cf482ec2d07c3"""
    var check1 = fromHex(stripSpaces(signature))
    var check2 = fromHex(stripSpaces(pubkey))
    var sig: Signature
    var key: PublicKey
    var s = keccak256.digest("sec").data
    var m = keccak256.digest("msg").data
    check signMessage(s, m, sig) == Success
    var sersig = sig.getRaw().data
    check recoverSignatureKey(sersig, m, key) == Success
    var serkey = key.getRaw().data
    check:
      compare(sersig, check1) == true
      compare(serkey, check2) == true

  test "ECDSA/100 signatures":
    # signature test
    var rkey: PublicKey
    var sig: Signature
    for i in 1..100:
      var m = newPrivateKey()
      var s = newPrivateKey()
      var key = s.getPublicKey()
      check signMessage(s, m, sig) == Success
      var sersig = sig.getRaw().data
      check:
        recoverSignatureKey(sersig, m, rkey) == Success
        key == rkey

  test "KEYS/100 create/recovery keys":
    # key create/recovery test
    var rkey: PublicKey
    for i in 1..100:
      var s = newPrivateKey()
      var key = s.getPublicKey()
      check:
        recoverPublicKey(key.getRaw().data, rkey) == Success
        key == rkey

  test "ECDHE/100 shared secrets":
    # ECDHE shared secret test
    var secret1, secret2: SharedSecret
    for i in 1..100:
      var aliceSecret = newPrivateKey()
      var alicePublic = aliceSecret.getPublicKey()
      var bobSecret = newPrivateKey()
      var bobPublic = bobSecret.getPublicKey()
      check:
        ecdhAgree(aliceSecret, bobPublic, secret1) == Success
        ecdhAgree(bobSecret, alicePublic, secret2) == Success
        secret1 == secret2
