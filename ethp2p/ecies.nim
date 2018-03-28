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
