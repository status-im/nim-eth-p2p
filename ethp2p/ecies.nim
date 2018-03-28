#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements ECIES method encryption/decryption.

import ecc, nimcrypto/sha2, nimcrypto/hash, nimcrypto/hmac
import nimcrypto/rijndael, nimcrypto/utils, nimcrypto/sysrand
import nimcrypto/bcmode, nimcrypto/utils

type
  EciesException* = object of Exception
  EciesStatus* = enum
    Success,        ## Operation was successful
    BufferOverrun,  ## Output buffer size is too small
    EmptyMessage,   ## Attempt to encrypt/decrypt empty message
    RandomError,    ## Could not obtain random data
    EcdhError,      ## ECDH shared secret could not be calculated
    IncorrectSize,  ## ECIES data has incorrect size (size is too low)
    WrongHeader,    ## ECIES header is incorrect
    IncorrectKey,   ## Recovered public key is invalid
    IncorrectTag    ## ECIES tag verification failed

template eciesOverheadLength*(): int =
  ## Return data overhead size for ECIES encrypted message
  1 + sizeof(PublicKey) + aes128.sizeBlock + sha256.sizeDigest

template eciesEncryptedLength*(size: int): int =
  ## Return size of encrypted message for message with size `size`.
  size + eciesOverheadLength()

template eciesDecryptedLength*(size: int): int =
  ## Return size of decrypted message for encrypted message with size `size`.
  size - eciesOverheadLength()

template eciesMacLength(size: int): int =
  ## Return size of authenticated data
  size + aes128.sizeBlock

template eciesMacPos(size: int): int =
  ## Return position of MAC code in encrypted block
  size - sha256.sizeDigest

template eciesIvPos(): int =
  ## Return position of IV in encrypted block
  sizeof(PublicKey) + 1

template eciesDataPos(): int =
  ## Return position of encrypted data in block
  sizeof(PublicKey) + 1 + aes128.sizeBlock

proc kdf*(data: openarray[byte]): array[KeyLength, byte] {.noInit.} =
  ## NIST SP 800-56a Concatenation Key Derivation Function (see section 5.8.1)
  var ctx: sha256
  var counter: uint32
  var counterLe: uint32
  let reps = ((KeyLength + 7) * 8) div (int(ctx.sizeDigest) * 8)
  var offset = 0
  var storage = newSeq[byte](KeyLength * (reps + 1))
  while counter <= uint32(reps):
    counter = counter + 1
    counterLe = LSWAP(counter)
    ctx.init()
    ctx.update(cast[ptr byte](addr counterLe), uint(sizeof(uint32)))
    ctx.update(unsafeAddr data[0], uint(len(data)))
    var hash = ctx.finish().data
    copyMem(addr storage[offset], addr hash[0], ctx.sizeDigest)
    offset = offset + int(ctx.sizeDigest)
  ctx.init() # clean ctx
  copyMem(addr result[0], addr storage[0], KeyLength)

proc eciesEncrypt*(inp, oup: ptr byte, inl, oul: int, pubkey: PublicKey,
                   shmac: ptr byte = nil, shlen: int = 0): EciesStatus =
  ## Encrypt data with ECIES method to the given public key `pubkey`.
  ##
  ## `inp`    - [INPUT] pointer to input data
  ## `oup`    - [INPUT] pointer to output data
  ## `inl`    - [INPUT] input data size
  ## `oul`    - [INPUT] output data size
  ## `pubkey` - [INPUT] Ecc secp256k1 public key
  ## `shmac`  - [INPUT] additional mac data
  ## `shlen`  - [INPUT] additional mac data size

  var
    encKey: array[KeyLength div 2, byte]
    macKey: array[KeyLength, byte]
    cipher: CTR[aes128]
    ctx: HMAC[sha256]
    iv: array[aes128.sizeBlock, byte]
    tag: array[sha256.sizeDigest, byte]
    secret: SharedSecret
    material: array[KeyLength, byte]

  assert(not isNil(inp) and not isNil(oup))
  assert(inl > 0 and oul > 0)

  if oul < eciesEncryptedLength(inl):
    return(BufferOverrun)
  if randomBytes(addr iv[0], len(iv)) != len(iv):
    return(RandomError)

  var ephemeral = newKeyPair()
  var output = cast[ptr UncheckedArray[byte]](oup)
  var epub = ephemeral.pubkey.getRaw()

  if ecdhAgree(ephemeral.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)

  material = kdf(secret)
  zeroMem(addr secret[0], sizeof(SharedSecret)) # clean shared secret
  copyMem(addr encKey[0], addr material[0], KeyLength div 2)
  macKey = sha256.digest(material, KeyLength div 2).data
  zeroMem(addr material[0], KeyLength) # clean material

  cipher.init(addr encKey[0], addr iv[0])
  cipher.encrypt(inp, cast[ptr byte](addr output[eciesDataPos()]), uint(inl))
  zeroMem(addr encKey[0], KeyLength div 2) # clean encKey
  zeroMem(addr cipher, sizeof(CTR[aes128])) # clean cipher context

  output[0] = 0x04
  copyMem(addr output[1], addr epub.data[0], sizeof(PublicKey))
  copyMem(addr output[eciesIvPos()], addr iv[0], aes128.sizeBlock)

  ctx.init(addr macKey[0], uint(len(macKey)))
  ctx.update(addr output[eciesIvPos()], uint(eciesMacLength(inl)))
  if not isNil(shmac) and shlen > 0:
    ctx.update(shmac, uint(shlen))
  tag = ctx.finish().data
  zeroMem(addr ctx, sizeof(HMAC[sha256])) # clean hmac context
  zeroMem(addr macKey[0], KeyLength) # clean macKey
  copyMem(addr output[eciesDataPos() + inl], addr tag[0], sha256.sizeDigest)
  result = Success

proc eciesDecrypt*(inp, oup: ptr byte, inl, oul: int, seckey: PrivateKey,
                   shmac: ptr byte = nil, shlen: int = 0): EciesStatus =
  ## Decrypt data with ECIES method using the given private key `seckey`.
  ##
  ## `inp`    - [INPUT] pointer to input data
  ## `oup`    - [INPUT] pointer to output data
  ## `inl`    - [INPUT] input data size
  ## `oul`    - [INPUT] output data size
  ## `seckey` - [INPUT] Ecc secp256k1 private key
  ## `shmac`  - [INPUT] additional mac data (default = nil)
  ## `shlen`  - [INPUT] additional mac data size (default = 0)

  var
    pubkey: PublicKey
    encKey: array[KeyLength div 2, byte]
    macKey: array[KeyLength, byte]
    tag: array[sha256.sizeDigest, byte]
    cipher: CTR[aes128]
    ctx: HMAC[sha256]
    secret: SharedSecret

  assert(not isNil(inp) and not isNil(oup))
  assert(inl > 0 and oul > 0)

  var input = cast[ptr UncheckedArray[byte]](inp)
  if inl <= eciesOverheadLength():
    return(IncorrectSize)
  if inl - eciesOverheadLength() > oul:
    return(BufferOverrun)
  if input[0] != 0x04:
    return(WrongHeader)

  if recoverPublicKey(addr input[1], KeyLength * 2,
                      pubkey) != EccStatus.Success:
    return(IncorrectKey)
  if ecdhAgree(seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)

  var material = kdf(secret)
  zeroMem(addr secret[0], sizeof(SharedSecret)) # clean shared secret
  copyMem(addr encKey[0], addr material[0], KeyLength div 2)
  macKey = sha256.digest(material, KeyLength div 2).data
  zeroMem(addr material[0], KeyLength) # clean material

  let macsize = eciesMacLength(inl - eciesOverheadLength())
  ctx.init(addr macKey[0], uint(len(macKey)))

  ctx.update(addr input[eciesIvPos()], uint(macsize))
  if not isNil(shmac) and shlen > 0:
    ctx.update(shmac, uint(shlen))
  tag = ctx.finish().data
  zeroMem(addr ctx, sizeof(HMAC[sha256])) # clean hmac context
  zeroMem(addr macKey[0], KeyLength) # clean macKey

  if not equalMem(addr tag[0], addr input[eciesMacPos(inl)], sha256.sizeDigest):
    return(IncorrectTag)

  cipher.init(addr encKey[0], addr input[eciesIvPos()])
  cipher.decrypt(cast[ptr byte](addr input[eciesDataPos()]),
                 cast[ptr byte](oup), uint(inl - eciesOverheadLength()))

  zeroMem(addr encKey[0], KeyLength div 2) # clean encKey
  zeroMem(addr cipher, sizeof(CTR[aes128])) # clean cipher context
  result = Success

proc eciesEncrypt*[A, B](input: openarray[A],
                         pubkey: PublicKey,
                         output: var openarray[B],
                         outlen: var int,
                         ostart: int = 0,
                         ofinish: int = -1): EciesStatus =
  ## Encrypt data with ECIES method to the given public key `pubkey`.
  ##
  ## `input`   - [INPUT] input data
  ## `pubkey`  - [INPUT] Ecc secp256k1 public key
  ## `output`  - [OUTPUT] output data
  ## `outlen`  - [OUTPUT] output data size
  ## `ostart`  - [INPUT] starting index in `data` (default = -1, start of input)
  ## `ofinish` - [INPUT] ending index in `data` (default = -1, whole input)
  ##
  ## Encryption is done on `data` with inclusive range [ostart, ofinish]
  ## Negative values of `ostart` and `ofinish` are treated as index with value
  ## (len(data) + `ostart/ofinish`).

  let so = if ostart < 0: (len(input) + ostart) else: ostart
  let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(A)
  # We don't need to check `so` because compiler will do it for `data[so]`.
  if eo >= len(input):
    return(BufferOverrun)
  if len(input) == 0:
    return(EmptyMessage)
  let esize = eciesEncryptedLength(length)
  if (len(output) * sizeof(B)) < esize:
    return(BufferOverrun)
  outlen = esize
  result = eciesEncrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
                        length, esize, pubkey)

proc eciesEncrypt*[A, B, C](input: openarray[A],
                            pubkey: PublicKey,
                            output: var openarray[B],
                            outlen: var int,
                            shmac: openarray[C],
                            ostart: int = 0,
                            ofinish: int = -1): EciesStatus =
  ## Encrypt data with ECIES method to the given public key `pubkey`.
  ##
  ## `input`   - [INPUT] input data
  ## `pubkey`  - [INPUT] Ecc secp256k1 public key
  ## `output`  - [OUTPUT] output data
  ## `outlen`  - [OUTPUT] output data size
  ## `shmac`   - [INPUT] additional mac data
  ## `ostart`  - [INPUT] starting index in `data` (default = -1, start of input)
  ## `ofinish` - [INPUT] ending index in `data` (default = -1, whole input)
  ##
  ## Encryption is done on `data` with inclusive range [ostart, ofinish]
  ## Negative values of `ostart` and `ofinish` are treated as index with value
  ## (len(data) + `ostart/ofinish`).

  let so = if ostart < 0: (len(input) + ostart) else: ostart
  let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(A)
  # We don't need to check `so` because compiler will do it for `data[so]`.
  if eo >= len(input):
    return(BufferOverrun)
  if len(input) == 0:
    return(EmptyMessage)
  let esize = eciesEncryptedLength(length)
  if len(output) * sizeof(B) < esize:
    return(BufferOverrun)
  outlen = esize
  result = eciesEncrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
                        length, esize, pubkey,
                        cast[ptr byte](unsafeAddr shmac[0]),
                        len(shmac) * sizeof(C))

proc eciesDecrypt*[A, B](input: openarray[A],
                         seckey: PrivateKey,
                         output: var openarray[B],
                         outlen: var int,
                         ostart: int = 0,
                         ofinish: int = -1): EciesStatus =
  ## Decrypt data with ECIES method using given private key `seckey`.
  ##
  ## `input`   - [INPUT] input data
  ## `seckey`  - [INPUT] Ecc secp256k1 private key
  ## `output`  - [OUTPUT] output data
  ## `outlen`  - [OUTPUT] output data size
  ## `ostart`  - [INPUT] starting index in `data` (default = -1, start of input)
  ## `ofinish` - [INPUT] ending index in `data` (default = -1, whole input)
  ##
  ## Decryption is done on `data` with inclusive range [ostart, ofinish]

  let so = if ostart < 0: (len(input) + ostart) else: ostart
  let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(A)
  # We don't need to check `so` because compiler will do it for `data[so]`.
  if eo >= len(input):
    return(BufferOverrun)
  if len(input) == 0:
    return(EmptyMessage)
  let dsize = eciesDecryptedLength(length)
  if len(output) * sizeof(B) < dsize:
    return(BufferOverrun)
  outlen = dsize
  result = eciesDecrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
                        length, dsize, seckey)

proc eciesDecrypt*[A, B, C](input: openarray[A],
                            seckey: PrivateKey,
                            output: var openarray[B],
                            outlen: var int,
                            shmac: openarray[C],
                            ostart: int = 0,
                            ofinish: int = -1): EciesStatus =
  ## Decrypt data with ECIES method using given private key `seckey`.
  ##
  ## `input`   - [INPUT] input data
  ## `seckey`  - [INPUT] Ecc secp256k1 private key
  ## `output`  - [OUTPUT] output data
  ## `outlen`  - [OUTPUT] output data size
  ## `shmac`   - additional mac data
  ## `ostart`  - starting index in `data` (default = -1, data[0])
  ## `ofinish` - ending index in `data` (default = -1, data[len(data) - 1])
  ##
  ## Decryption is done on `data` with inclusive range [ostart, ofinish]

  let so = if ostart < 0: (len(input) + ostart) else: ostart
  let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(A)
  # We don't need to check `so` because compiler will do it for `data[so]`.
  if eo >= len(input):
    return(BufferOverrun)
  if len(input) == 0:
    return(EmptyMessage)
  let dsize = eciesDecryptedLength(length)
  if len(output) * sizeof(B) < dsize:
    return(BufferOverrun)
  outlen = dsize
  result = eciesDecrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
                        length, dsize, seckey,
                        cast[ptr byte](unsafeAddr shmac[0]),
                        len(shmac) * sizeof(C))

when isMainModule:
  proc compare[A, B](x: openarray[A], y: openarray[B], s: int = 0): bool =
    result = true
    assert(s >= 0)
    var size = if s == 0: min(len(x), len(y)) else: min(s, min(len(x), len(y)))
    for i in 0..(size - 1):
      if x[i] != cast[A](y[i]):
        result = false
        break

  block:
    # KDF test
    # Copied from https://github.com/ethereum/pydevp2p/blob/develop/devp2p/tests/test_ecies.py#L53
    let m0 = "961c065873443014e0371f1ed656c586c6730bf927415757f389d92acf8268df"
    let c0 = "4050c52e6d9c08755e5a818ac66fabe478b825b1836fd5efc4d44e40d04dabcc"
    var m = fromHex(stripSpaces(m0))
    var c = fromHex(stripSpaces(c0))
    var k = kdf(m)
    doAssert(compare(k, c))

  block:
    # HMAC-SHA256 test
    # https://github.com/ethereum/py-evm/blob/master/tests/p2p/test_ecies.py#L64-L76
    const keys = [
      "07a4b6dfa06369a570f2dcba2f11a18f",
      "af6623e52208c596e17c72cea6f1cb09"
    ]
    const datas = ["4dcb92ed4fc67fe86832", "3461282bcedace970df2"]
    const expects = [
      "c90b62b1a673b47df8e395e671a68bfa68070d6e2ef039598bb829398b89b9a9",
      "b3ce623bce08d5793677ba9441b22bb34d3e8a7de964206d26589df3e8eb5183"
    ]
    for i in 0..1:
      var k = fromHex(stripSpaces(keys[i]))
      var m = fromHex(stripSpaces(datas[i]))
      var digest = sha256.hmac(k, m).data
      var check = fromHex(stripSpaces(expects[i]))
      doAssert(compare(digest, check))

  block:
    # ECIES encryption
    var m = "Hello World!"
    var encr = newSeq[byte](eciesEncryptedLength(len(m)))
    var decr = newSeq[byte](len(m))
    var shmac = [0x13'u8, 0x13'u8]
    var outlen = 0
    var s = newPrivateKey()
    var p = s.getPublicKey()
    # Without additional mac data
    doAssert(eciesEncrypt(m, p, encr, outlen) == Success)
    doAssert(eciesDecrypt(encr, s, decr, outlen) == Success)
    doAssert(outlen == len(m))
    doAssert(equalMem(addr m[0], addr decr[0], outlen))
    # With additional mac data
    doAssert(eciesEncrypt(m, p, encr, outlen, shmac) == Success)
    doAssert(eciesDecrypt(encr, s, decr, outlen, shmac) == Success)
    doAssert(outlen == len(m))
    doAssert(equalMem(addr m[0], addr decr[0], outlen))

  block:
    # ECIES
    # https://github.com/ethereum/py-evm/blob/master/tests/p2p/test_ecies.py#L43
    # https://github.com/ethereum/cpp-ethereum/blob/develop/test/unittests/libp2p/rlpx.cpp#L187
    const secretKeys = [
      "c45f950382d542169ea207959ee0220ec1491755abe405cd7498d6b16adb6df8",
      "5e173f6ac3c669587538e7727cf19b782a4f2fda07c1eaa662c593e5e85e3051"
    ]
    const cipherText = [
      """04a0274c5951e32132e7f088c9bdfdc76c9d91f0dc6078e848f8e3361193dbdc
         43b94351ea3d89e4ff33ddcefbc80070498824857f499656c4f79bbd97b6c51a
         514251d69fd1785ef8764bd1d262a883f780964cce6a14ff206daf1206aa073a
         2d35ce2697ebf3514225bef186631b2fd2316a4b7bcdefec8d75a1025ba2c540
         4a34e7795e1dd4bc01c6113ece07b0df13b69d3ba654a36e35e69ff9d482d88d
         2f0228e7d96fe11dccbb465a1831c7d4ad3a026924b182fc2bdfe016a6944312
         021da5cc459713b13b86a686cf34d6fe6615020e4acf26bf0d5b7579ba813e77
         23eb95b3cef9942f01a58bd61baee7c9bdd438956b426a4ffe238e61746a8c93
         d5e10680617c82e48d706ac4953f5e1c4c4f7d013c87d34a06626f498f34576d
         c017fdd3d581e83cfd26cf125b6d2bda1f1d56""",
      """049934a7b2d7f9af8fd9db941d9da281ac9381b5740e1f64f7092f3588d4f87f
         5ce55191a6653e5e80c1c5dd538169aa123e70dc6ffc5af1827e546c0e958e42
         dad355bcc1fcb9cdf2cf47ff524d2ad98cbf275e661bf4cf00960e74b5956b79
         9771334f426df007350b46049adb21a6e78ab1408d5e6ccde6fb5e69f0f4c92b
         b9c725c02f99fa72b9cdc8dd53cff089e0e73317f61cc5abf6152513cb7d833f
         09d2851603919bf0fbe44d79a09245c6e8338eb502083dc84b846f2fee1cc310
         d2cc8b1b9334728f97220bb799376233e113"""
    ]
    const expectText = [
      """884c36f7ae6b406637c1f61b2f57e1d2cab813d24c6559aaf843c3f48962f32f
         46662c066d39669b7b2e3ba14781477417600e7728399278b1b5d801a519aa57
         0034fdb5419558137e0d44cd13d319afe5629eeccb47fd9dfe55cc6089426e46
         cc762dd8a0636e07a54b31169eba0c7a20a1ac1ef68596f1f283b5c676bae406
         4abfcce24799d09f67e392632d3ffdc12e3d6430dcb0ea19c318343ffa7aae74
         d4cd26fecb93657d1cd9e9eaf4f8be720b56dd1d39f190c4e1c6b7ec66f077bb
         1100""",
      """802b052f8b066640bba94a4fc39d63815c377fced6fcb84d27f791c9921ddf3e
         9bf0108e298f490812847109cbd778fae393e80323fd643209841a3b7f110397
         f37ec61d84cea03dcc5e8385db93248584e8af4b4d1c832d8c7453c0089687a7
         00"""
    ]
    var data: array[1024, byte]
    var outlen = 0
    for i in 0..1:
      var s = secretKeys[i].getPrivateKey()
      var cipher = fromHex(stripSpaces(cipherText[i]))
      var check = fromHex(stripSpaces(expectText[i]))
      var r = eciesDecrypt(cipher, s, data, outlen)
      doAssert(r == Success, $r)
      doAssert(outlen == len(check))
      doAssert(compare(data, check))

  block:
    # ECIES
    # https://github.com/ethereum/cpp-ethereum/blob/develop/test/unittests/libp2p/rlpx.cpp#L432-L459
    const secretKeys = [
      "57baf2c62005ddec64c357d96183ebc90bf9100583280e848aa31d683cad73cb",
      "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b",
      "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b",
      "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b"
    ]
    const cipherData = [
      """04ff2c874d0a47917c84eea0b2a4141ca95233720b5c70f81a8415bae1dc7b74
         6b61df7558811c1d6054333907333ef9bb0cc2fbf8b34abb9730d14e0140f455
         3f4b15d705120af46cf653a1dc5b95b312cf8444714f95a4f7a0425b67fc064d
         18f4d0a528761565ca02d97faffdac23de10""",
      """046f647e1bd8a5cd1446d31513bac233e18bdc28ec0e59d46de453137a725995
         33f1e97c98154343420d5f16e171e5107999a7c7f1a6e26f57bcb0d2280655d0
         8fb148d36f1d4b28642d3bb4a136f0e33e3dd2e3cffe4b45a03fb7c5b5ea5e65
         617250fdc89e1a315563c20504b9d3a72555""",
      """0443c24d6ccef3ad095140760bb143078b3880557a06392f17c5e368502d7953
         2bc18903d59ced4bbe858e870610ab0d5f8b7963dd5c9c4cf81128d10efd7c7a
         a80091563c273e996578403694673581829e25a865191bdc9954db14285b56eb
         0043b6288172e0d003c10f42fe413222e273d1d4340c38a2d8344d7aadcbc846
         ee""",
      """04c4e40c86bb5324e017e598c6d48c19362ae527af8ab21b077284a4656c8735
         e62d73fb3d740acefbec30ca4c024739a1fcdff69ecaf03301eebf156eb5f17c
         ca6f9d7a7e214a1f3f6e34d1ee0ec00ce0ef7d2b242fbfec0f276e17941f9f1b
         fbe26de10a15a6fac3cda039904ddd1d7e06e7b96b4878f61860e47f0b84c8ce
         b64f6a900ff23844f4359ae49b44154980a626d3c73226c19e"""
    ]
    const expectData = [
      "a", "a", "aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ]
    var data: array[1024, byte]
    var outlen = 0
    for i in 0..3:
      var s = secretKeys[i].getPrivateKey()
      var cipher = fromHex(stripSpaces(cipherData[i]))
      doAssert(eciesDecrypt(cipher, s, data, outlen) == Success)
      doAssert(outlen == len(expectData[i]))
      doAssert(compare(data, expectData[i]))
