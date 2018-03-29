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

const
  emptyMac* = array[0, byte]([])

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
    IncorrectTag,   ## ECIES tag verification failed
    IncompleteError ## Decryption needs more data

  EciesHeader* = object {.packed.}
    version*: byte
    pubkey*: array[PublicKeyLength, byte]
    iv*: array[aes128.sizeBlock, byte]
    data*: byte

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

template eciesDataPos(): int =
  ## Return position of encrypted data in block
  1 + sizeof(PublicKey) + aes128.sizeBlock

template eciesIvPos(): int =
  ## Return position of IV in block
  1 + sizeof(PublicKey)

template eciesTagPos(size: int): int =
  1 + sizeof(PublicKey) + aes128.sizeBlock + size

proc kdf*(data: openarray[byte]): array[KeyLength, byte] {.noInit.} =
  ## NIST SP 800-56a Concatenation Key Derivation Function (see section 5.8.1)
  var ctx: sha256
  var counter: uint32
  var counterLe: uint32
  let reps = ((KeyLength + 7) * 8) div (int(ctx.sizeDigest) * 8)
  var offset = 0
  # REVIEW: There is a relationship between KeyLength and sha256.sizeDigest here
  # that could be expressed in the code with a static assert.
  var storage = newSeq[byte](KeyLength * (reps + 1))
  while counter <= uint32(reps):
    counter = counter + 1
    counterLe = LSWAP(counter)
    ctx.init()
    ctx.update(cast[ptr byte](addr counterLe), uint(sizeof(uint32)))
    ctx.update(unsafeAddr data[0], uint(len(data)))
    var hash = ctx.finish()
    copyMem(addr storage[offset], addr hash.data[0], ctx.sizeDigest)
    offset += int(ctx.sizeDigest)
  ctx.clear() # clean ctx
  copyMem(addr result[0], addr storage[0], KeyLength)

proc eciesEncrypt*(input: openarray[byte], output: var openarray[byte],
                   pubkey: PublicKey,
                   sharedmac: openarray[byte]): EciesStatus =
  ## Encrypt data with ECIES method using given public key `pubkey`.
  ## ``input``     - input data
  ## ``output``    - output data
  ## ``pubkey``    - ECC public key
  ## ``sharedmac`` - additional data used to calculate encrypted message MAC
  ## Length of output data can be calculated using ``eciesEncryptedLength()``
  ## macro.
  var
    encKey: array[aes128.sizeKey, byte]
    cipher: CTR[aes128]
    ctx: HMAC[sha256]
    iv: array[aes128.sizeBlock, byte]
    secret: SharedSecret
    material: array[KeyLength, byte]

  if len(output) < eciesEncryptedLength(len(input)):
    return(BufferOverrun)
  if randomBytes(iv) != aes128.sizeBlock:
    return(RandomError)

  var ephemeral = newKeyPair()
  var epub = ephemeral.pubkey.getRaw()

  if ecdhAgree(ephemeral.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)

  material = kdf(secret)
  burnMem(secret)

  copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
  var macKey = sha256.digest(material, ostart = KeyLength div 2)
  burnMem(material)

  var header = cast[ptr EciesHeader](addr output[0])
  header.version = 0x04
  header.pubkey = epub.data
  header.iv = iv

  var so = eciesDataPos()
  var eo = so + len(input)
  cipher.init(encKey, iv)
  cipher.encrypt(input, toOpenArray(output, so, eo))
  burnMem(encKey)
  cipher.clear()

  so = eciesIvPos()
  eo = so + aes128.sizeBlock + len(input)
  ctx.init(macKey.data)
  ctx.update(toOpenArray(output, so, eo))
  if len(sharedmac) > 0:
    ctx.update(sharedmac)
  var tag = ctx.finish()

  so = eciesTagPos(len(input))
  copyMem(addr output[so], addr tag.data[0], ctx.sizeDigest)
  ctx.clear()

  result = Success

proc eciesDecrypt*(input: openarray[byte],
                   output: var openarray[byte],
                   seckey: PrivateKey,
                   sharedmac: openarray[byte]): EciesStatus =
  ## Decrypt data with ECIES method using given private key `seckey`.
  ## ``input``     - input data
  ## ``output``    - output data
  ## ``pubkey``    - ECC private key
  ## ``sharedmac`` - additional data used to calculate encrypted message MAC
  ## Length of output data can be calculated using ``eciesDecryptedLength()``
  ## macro.
  var
    pubkey: PublicKey
    encKey: array[aes128.sizeKey, byte]
    cipher: CTR[aes128]
    ctx: HMAC[sha256]
    secret: SharedSecret

  if len(input) == 0:
    return(IncompleteError)

  var header = cast[ptr EciesHeader](unsafeAddr input[0])
  if header.version != 0x04:
    return(WrongHeader)
  if len(input) <= eciesOverheadLength():
    return(IncompleteError)
  if len(input) - eciesOverheadLength() > len(output):
    return(BufferOverrun)
  if recoverPublicKey(header.pubkey, pubkey) != EccStatus.Success:
    return(IncorrectKey)
  if ecdhAgree(seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)

  var material = kdf(secret)
  burnMem(secret)
  copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
  var macKey = sha256.digest(material, ostart = KeyLength div 2)
  burnMem(material)

  let macsize = eciesMacLength(len(input) - eciesOverheadLength())
  let datsize = eciesDecryptedLength(len(input))
  ctx.init(macKey.data)
  burnMem(macKey)
  ctx.update(toOpenArray(input, eciesIvPos(), eciesIvPos() + macsize))
  if len(sharedmac) > 0:
    ctx.update(sharedmac)
  var tag = ctx.finish()
  ctx.clear()

  if not equalMem(addr tag.data[0], unsafeAddr input[eciesMacPos(len(input))],
                  sha256.sizeDigest):
    return(IncorrectTag)

  cipher.init(encKey, header.iv)
  burnMem(encKey)
  cipher.decrypt(toOpenArray(input, eciesDataPos(), eciesDataPos() + datsize),
                 output)
  cipher.clear()
  result = Success


# proc eciesEncrypt*(inp, oup: ptr byte, inl, oul: int, pubkey: PublicKey,
#                    shmac: ptr byte = nil, shlen: int = 0): EciesStatus =
#   ## Encrypt data with ECIES method to the given public key `pubkey`.
#   ##
#   ## `inp`    - [INPUT] pointer to input data
#   ## `oup`    - [INPUT] pointer to output data
#   ## `inl`    - [INPUT] input data size
#   ## `oul`    - [INPUT] output data size
#   ## `pubkey` - [INPUT] Ecc secp256k1 public key
#   ## `shmac`  - [INPUT] additional mac data
#   ## `shlen`  - [INPUT] additional mac data size

#   var
#     encKey: array[aes128.sizeKey, byte]
#     cipher: CTR[aes128]
#     ctx: HMAC[sha256]
#     iv: array[aes128.sizeBlock, byte]
#     secret: SharedSecret
#     material: array[KeyLength, byte]

#   assert(not isNil(inp) and not isNil(oup))
#   assert(inl > 0 and oul > 0)

#   if oul < eciesEncryptedLength(inl):
#     return(BufferOverrun)
#   if randomBytes(addr iv[0], len(iv)) != len(iv):
#     return(RandomError)

#   var ephemeral = newKeyPair()
#   var output = cast[ptr UncheckedArray[byte]](oup)
#   var epub = ephemeral.pubkey.getRaw()

#   if ecdhAgree(ephemeral.seckey, pubkey, secret) != EccStatus.Success:
#     return(EcdhError)

#   material = kdf(secret)
#   burnMem(secret)

#   copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
#   var macKey = sha256.digest(material, ostart = KeyLength div 2)
#   burnMem(material)

#   var header = cast[ptr EciesHeader](oup)
#   header.version = 0x04
#   header.pubkey = epub.data
#   header.iv = iv

#   cipher.init(addr encKey[0], addr iv[0])
#   cipher.encrypt(inp, cast[ptr byte](addr header.data), uint(inl))
#   burnMem(encKey)
#   cipher.clear()

#   ctx.init(cast[ptr byte](addr macKey.data[0]), uint(sha256.sizeDigest))
#   burnMem(macKey)
#   ctx.update(cast[ptr byte](addr header.iv), uint(eciesMacLength(inl)))
#   if not isNil(shmac) and shlen > 0:
#     ctx.update(shmac, uint(shlen))
#   var tag = ctx.finish()
#   ctx.clear()

#   # echo dump(output, oul)

#   let tagPos = cast[ptr byte](cast[uint](addr header.data) + uint(inl))
#   copyMem(tagPos, addr tag.data[0], sha256.sizeDigest)
#   result = Success

# proc eciesDecrypt*(inp, oup: ptr byte, inl, oul: int, seckey: PrivateKey,
#                    shmac: ptr byte = nil, shlen: int = 0): EciesStatus =
#   ## Decrypt data with ECIES method using the given private key `seckey`.
#   ##
#   ## `inp`    - [INPUT] pointer to input data
#   ## `oup`    - [INPUT] pointer to output data
#   ## `inl`    - [INPUT] input data size
#   ## `oul`    - [INPUT] output data size
#   ## `seckey` - [INPUT] Ecc secp256k1 private key
#   ## `shmac`  - [INPUT] additional mac data (default = nil)
#   ## `shlen`  - [INPUT] additional mac data size (default = 0)

#   var
#     pubkey: PublicKey
#     encKey: array[aes128.sizeKey, byte]
#     cipher: CTR[aes128]
#     ctx: HMAC[sha256]
#     secret: SharedSecret

#   assert(not isNil(inp) and not isNil(oup))
#   assert(inl > 0 and oul > 0)

#   var input = cast[ptr UncheckedArray[byte]](inp)
#   if inl <= eciesOverheadLength():
#     return(IncorrectSize)
#   if inl - eciesOverheadLength() > oul:
#     return(BufferOverrun)

#   var header = cast[ptr EciesHeader](input)
#   if header.version != 0x04:
#     return(WrongHeader)

#   if recoverPublicKey(addr input[1], KeyLength * 2,
#                       pubkey) != EccStatus.Success:
#     return(IncorrectKey)

#   if ecdhAgree(seckey, pubkey, secret) != EccStatus.Success:
#     return(EcdhError)

#   var material = kdf(secret)
#   burnMem(secret)
#   copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
#   var macKey = sha256.digest(material, ostart = KeyLength div 2)
#   burnMem(material)

#   let macsize = eciesMacLength(inl - eciesOverheadLength())
#   ctx.init(addr macKey.data[0], uint(sha256.sizeDigest))
#   burnMem(macKey)
#   ctx.update(cast[ptr byte](addr header.iv), uint(macsize))
#   if not isNil(shmac) and shlen > 0:
#     ctx.update(shmac, uint(shlen))
#   var tag = ctx.finish()
#   ctx.clear()

#   if not equalMem(addr tag.data[0], addr input[eciesMacPos(inl)],
#                   sha256.sizeDigest):
#     return(IncorrectTag)

#   cipher.init(addr encKey[0], cast[ptr byte](addr header.iv))
#   burnMem(encKey)
#   cipher.decrypt(cast[ptr byte](addr header.data),
#                  cast[ptr byte](oup), uint(inl - eciesOverheadLength()))
#   cipher.clear()
#   result = Success

# proc eciesEncrypt*[A, B](input: openarray[A],
#                          pubkey: PublicKey,
#                          output: var openarray[B],
#                          outlen: var int,
#                          ostart: int = 0,
#                          ofinish: int = -1): EciesStatus =
#   ## Encrypt data with ECIES method to the given public key `pubkey`.
#   ##
#   ## `input`   - [INPUT] input data
#   ## `pubkey`  - [INPUT] Ecc secp256k1 public key
#   ## `output`  - [OUTPUT] output data
#   ## `outlen`  - [OUTPUT] output data size
#   ## `ostart`  - [INPUT] starting index in `data` (default = -1, start of input)
#   ## `ofinish` - [INPUT] ending index in `data` (default = -1, whole input)
#   ##
#   ## Encryption is done on `data` with inclusive range [ostart, ofinish]
#   ## Negative values of `ostart` and `ofinish` are treated as index with value
#   ## (len(data) + `ostart/ofinish`).

#   let so = if ostart < 0: (len(input) + ostart) else: ostart
#   let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
#   let length = (eo - so + 1) * sizeof(A)
#   # We don't need to check `so` because compiler will do it for `data[so]`.
#   if eo >= len(input):
#     return(BufferOverrun)
#   if len(input) == 0:
#     return(EmptyMessage)
#   let esize = eciesEncryptedLength(length)
#   if (len(output) * sizeof(B)) < esize:
#     return(BufferOverrun)
#   outlen = esize
#   result = eciesEncrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
#                         length, esize, pubkey)

# proc eciesEncrypt*[A, B, C](input: openarray[A],
#                             pubkey: PublicKey,
#                             output: var openarray[B],
#                             outlen: var int,
#                             shmac: openarray[C],
#                             ostart: int = 0,
#                             ofinish: int = -1): EciesStatus =
#   ## Encrypt data with ECIES method to the given public key `pubkey`.
#   ##
#   ## `input`   - [INPUT] input data
#   ## `pubkey`  - [INPUT] Ecc secp256k1 public key
#   ## `output`  - [OUTPUT] output data
#   ## `outlen`  - [OUTPUT] output data size
#   ## `shmac`   - [INPUT] additional mac data
#   ## `ostart`  - [INPUT] starting index in `data` (default = -1, start of input)
#   ## `ofinish` - [INPUT] ending index in `data` (default = -1, whole input)
#   ##
#   ## Encryption is done on `data` with inclusive range [ostart, ofinish]
#   ## Negative values of `ostart` and `ofinish` are treated as index with value
#   ## (len(data) + `ostart/ofinish`).

#   let so = if ostart < 0: (len(input) + ostart) else: ostart
#   let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
#   let length = (eo - so + 1) * sizeof(A)
#   # We don't need to check `so` because compiler will do it for `data[so]`.
#   if eo >= len(input):
#     return(BufferOverrun)
#   if len(input) == 0:
#     return(EmptyMessage)
#   let esize = eciesEncryptedLength(length)
#   if len(output) * sizeof(B) < esize:
#     return(BufferOverrun)
#   outlen = esize
#   result = eciesEncrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
#                         length, esize, pubkey,
#                         cast[ptr byte](unsafeAddr shmac[0]),
#                         len(shmac) * sizeof(C))

# proc eciesDecrypt*[A, B](input: openarray[A],
#                          seckey: PrivateKey,
#                          output: var openarray[B],
#                          outlen: var int,
#                          ostart: int = 0,
#                          ofinish: int = -1): EciesStatus =
#   ## Decrypt data with ECIES method using given private key `seckey`.
#   ##
#   ## `input`   - [INPUT] input data
#   ## `seckey`  - [INPUT] Ecc secp256k1 private key
#   ## `output`  - [OUTPUT] output data
#   ## `outlen`  - [OUTPUT] output data size
#   ## `ostart`  - [INPUT] starting index in `data` (default = -1, start of input)
#   ## `ofinish` - [INPUT] ending index in `data` (default = -1, whole input)
#   ##
#   ## Decryption is done on `data` with inclusive range [ostart, ofinish]

#   let so = if ostart < 0: (len(input) + ostart) else: ostart
#   let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
#   let length = (eo - so + 1) * sizeof(A)
#   # We don't need to check `so` because compiler will do it for `data[so]`.
#   if eo >= len(input):
#     return(BufferOverrun)
#   if len(input) == 0:
#     return(EmptyMessage)
#   let dsize = eciesDecryptedLength(length)
#   if len(output) * sizeof(B) < dsize:
#     return(BufferOverrun)
#   outlen = dsize
#   result = eciesDecrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
#                         length, dsize, seckey)

# proc eciesDecrypt*[A, B, C](input: openarray[A],
#                             seckey: PrivateKey,
#                             output: var openarray[B],
#                             outlen: var int,
#                             shmac: openarray[C],
#                             ostart: int = 0,
#                             ofinish: int = -1): EciesStatus =
#   ## Decrypt data with ECIES method using given private key `seckey`.
#   ##
#   ## `input`   - [INPUT] input data
#   ## `seckey`  - [INPUT] Ecc secp256k1 private key
#   ## `output`  - [OUTPUT] output data
#   ## `outlen`  - [OUTPUT] output data size
#   ## `shmac`   - additional mac data
#   ## `ostart`  - starting index in `data` (default = -1, data[0])
#   ## `ofinish` - ending index in `data` (default = -1, data[len(data) - 1])
#   ##
#   ## Decryption is done on `data` with inclusive range [ostart, ofinish]

#   let so = if ostart < 0: (len(input) + ostart) else: ostart
#   let eo = if ofinish < 0: (len(input) + ofinish) else: ofinish
#   let length = (eo - so + 1) * sizeof(A)
#   # We don't need to check `so` because compiler will do it for `data[so]`.
#   if eo >= len(input):
#     return(BufferOverrun)
#   if len(input) == 0:
#     return(EmptyMessage)
#   let dsize = eciesDecryptedLength(length)
#   if len(output) * sizeof(B) < dsize:
#     return(BufferOverrun)
#   outlen = dsize
#   result = eciesDecrypt(cast[ptr byte](unsafeAddr input[so]), addr output[0],
#                         length, dsize, seckey,
#                         cast[ptr byte](unsafeAddr shmac[0]),
#                         len(shmac) * sizeof(C))
