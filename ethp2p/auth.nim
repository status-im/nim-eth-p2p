#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements Ethereum authentication

import endians
import ecc, ecies, rlp
import nimcrypto/sysrand, nimcrypto/hash, nimcrypto/utils, nimcrypto/hmac
import nimcrypto/rijndael, nimcrypto/keccak, nimcrypto/sha2

const
  SupportedRlpxVersion* = 4
  PlainAuthMessageV4Length* = 194
  AuthMessageV4Length* = 307
  PlainAuthMessageEIP8Length = 169
  PlainAuthMessageMaxEIP8 = PlainAuthMessageEIP8Length + 255
  AuthMessageEIP8Length* = 282 + 2
  AuthMessageMaxEIP8* = AuthMessageEIP8Length + 255
  PlainAckMessageV4Length* = 97
  AckMessageV4Length* = 210
  PlainAckMessageEIP8Length = 102
  PlainAckMessageMaxEIP8 = PlainAckMessageEIP8Length + 255
  AckMessageEIP8Length = 215 + 2
  AckMessageMaxEIP8 = AckMessageEIP8Length + 255

type
  AuthMessageV4* = object {.packed.}
    signature: RawSignature
    keyhash: array[keccak256.sizeDigest, byte]
    pubkey: PublicKey
    nonce: array[keccak256.sizeDigest, byte]
    flag: byte

  AckMessageV4* = object {.packed.}
    pubkey: PublicKey
    nonce: array[keccak256.sizeDigest, byte]
    flag: byte

  HandshakeFlag* = enum
    Initiator,      ## `Handshake` owner is connection initiator
    Responder,      ## `Handshake` owner is connection responder
    Eip8            ## Flag indicates that EIP-8 handshake is used

  AuthStatus* = enum
    Success,        ## Operation was successful
    RandomError,    ## Could not obtain random data
    EcdhError,      ## ECDH shared secret could not be calculated
    BufferOverrun,  ## Buffer overrun error
    SignatureError, ## Signature could not be obtained
    EciesError,     ## ECIES encryption/decryption error
    InvalidPubKey,  ## Invalid public key
    InvalidAuth,    ## Invalid Authentication message
    InvalidAck,     ## Invalid Authentication ACK message
    RlpError,       ## Error while decoding RLP stream
    IncompleteError ## Data incomplete error

  Handshake* = object
    version*: uint8             ## protocol version
    flags*: set[HandshakeFlag]  ## handshake flags
    host*: KeyPair              ## host keypair
    ephemeral*: KeyPair         ## ephemeral host keypair
    remoteHPubkey*: PublicKey   ## remote host public key
    remoteEPubkey*: PublicKey   ## remote host ephemeral public key
    initiatorNonce*: Nonce      ## initiator nonce
    responderNonce*: Nonce      ## responder nonce

  ConnectionSecret* = object
    aesKey*: array[aes256.sizeKey, byte]
    macKey*: array[KeyLength, byte]
    egressMac*: array[keccak256.sizeDigest, byte]
    ingressMac*: array[keccak256.sizeDigest, byte]

  AuthException* = object of Exception

template toa(a, b, c: untyped): untyped =
  toOpenArray((a), (b), (b) + (c) - 1)

proc sxor[T](a: var openarray[T], b: openarray[T]) =
  assert(len(a) == len(b))
  for i in 0 ..< len(a):
    a[i] = a[i] xor b[i]

proc newHandshake*(flags: set[HandshakeFlag] = {Initiator},
                   version: int = SupportedRlpxVersion): Handshake =
  ## Create new `Handshake` object.
  result.version = byte(version and 0xFF)
  result.flags = flags
  result.ephemeral = newKeyPair()
  if Initiator in flags:
    if randomBytes(result.initiatorNonce) != len(result.initiatorNonce):
      raise newException(AuthException, "Could not obtain random data!")
  else:
    if randomBytes(result.responderNonce) != len(result.responderNonce):
      raise newException(AuthException, "Could not obtain random data!")

proc authMessagePreEIP8(h: var Handshake,
                        pubkey: PublicKey,
                        output: var openarray[byte],
                        outlen: var int,
                        flag: int = 0,
                        encrypt: bool = true): AuthStatus =
  ## Create plain pre-EIP8 authentication message.
  var
    secret: SharedSecret
    signature: Signature
    buffer: array[PlainAuthMessageV4Length, byte]
    flagb: byte
    header: ptr AuthMessageV4
  outlen = 0
  flagb = byte(flag)
  header = cast[ptr AuthMessageV4](addr buffer[0])
  if ecdhAgree(h.host.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)
  var xornonce = h.initiatorNonce
  xornonce.sxor(secret)
  if signMessage(h.ephemeral.seckey, xornonce, signature) != EccStatus.Success:
    return(SignatureError)
  h.remoteHPubkey = pubkey
  header.signature = signature.getRaw()
  header.keyhash = keccak256.digest(h.ephemeral.pubkey.getRaw().data).data
  header.pubkey = cast[PublicKey](h.host.pubkey.getRaw().data)
  header.nonce = h.initiatorNonce
  header.flag = flagb
  if encrypt:
    if len(output) < AuthMessageV4Length:
      return(BufferOverrun)
    if eciesEncrypt(buffer, output, h.remoteHPubkey) != EciesStatus.Success:
      return(EciesError)
    outlen = AuthMessageV4Length
    result = Success
  else:
    if len(output) < PlainAuthMessageV4Length:
      return(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], PlainAuthMessageV4Length)
    outlen = PlainAuthMessageV4Length
    result = Success

proc authMessageEIP8(h: var Handshake,
                     pubkey: PublicKey,
                     output: var openarray[byte],
                     outlen: var int,
                     flag: int = 0,
                     encrypt: bool = true): AuthStatus =
  ## Create EIP8 authentication message.
  var
    secret: SharedSecret
    signature: Signature
    buffer: array[PlainAuthMessageMaxEIP8, byte]
    padsize: byte

  assert(EIP8 in h.flags)
  outlen = 0
  if ecdhAgree(h.host.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)
  var xornonce = h.initiatorNonce
  xornonce.sxor(secret)
  if signMessage(h.ephemeral.seckey, xornonce, signature) != EccStatus.Success:
    return(SignatureError)
  h.remoteHPubkey = pubkey
  var payload = rlp.encodeList(signature.getRaw().data,
                               h.host.pubkey.getRaw().data,
                               h.initiatorNonce,
                               [byte(h.version)])
  assert(len(payload) == PlainAuthMessageEIP8Length)
  let pencsize = eciesEncryptedLength(len(payload))
  while true:
    if randomBytes(addr padsize, 1) != 1:
      return(RandomError)
    if int(padsize) > (AuthMessageV4Length - (pencsize + 2)):
      break
  # It is possible to make packet size constant by uncommenting this line
  # padsize = 24
  var wosize = pencsize + int(padsize)
  let fullsize = wosize + 2
  if randomBytes(toa(buffer, PlainAuthMessageEIP8Length,
                 int(padsize))) != int(padsize):
    return(RandomError)
  if encrypt:
    copyMem(addr buffer[0], payload.baseAddr, len(payload))
    if len(output) < fullsize:
      return(BufferOverrun)
    bigEndian16(addr output, addr wosize)
    if eciesEncrypt(toa(buffer, 0, len(payload) + int(padsize)),
                    toa(output, 2, wosize), pubkey,
                    toa(output, 0, 2)) != EciesStatus.Success:
      return(EciesError)
    outlen = fullsize
  else:
    let plainsize = len(payload) + int(padsize)
    if len(output) < plainsize:
      return(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], plainsize)
    outlen = plainsize
  result = Success

proc ackMessagePreEIP8(h: var Handshake,
                       output: var openarray[byte],
                       outlen: var int,
                       flag: int = 0,
                       encrypt: bool = true): AuthStatus =
  ## Create plain pre-EIP8 authentication ack message.
  var buffer: array[PlainAckMessageV4Length, byte]
  outlen = 0
  var header = cast[ptr AckMessageV4](addr buffer[0])
  header.pubkey = cast[PublicKey](h.ephemeral.pubkey.getRaw().data)
  header.nonce = h.responderNonce
  header.flag = byte(flag)
  if encrypt:
    if len(output) < AckMessageV4Length:
      return(BufferOverrun)
    if eciesEncrypt(buffer, output, h.remoteHPubkey) != EciesStatus.Success:
      return(EciesError)
    outlen = AckMessageV4Length
  else:
    if len(output) < PlainAckMessageV4Length:
      return(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], PlainAckMessageV4Length)
    outlen = PlainAckMessageV4Length
  result = Success

proc ackMessageEIP8(h: var Handshake,
                    output: var openarray[byte],
                    outlen: var int,
                    flag: int = 0,
                    encrypt: bool = true): AuthStatus =
  ## Create EIP8 authentication ack message.
  var
    buffer: array[PlainAckMessageMaxEIP8, byte]
    padsize: byte
  assert(EIP8 in h.flags)
  var payload = rlp.encodeList(h.ephemeral.pubkey.getRaw().data,
                               h.responderNonce,
                               [byte(h.version)])
  assert(len(payload) == PlainAckMessageEIP8Length)
  outlen = 0
  let pencsize = eciesEncryptedLength(len(payload))
  while true:
    if randomBytes(addr padsize, 1) != 1:
      return(RandomError)
    if int(padsize) > (AckMessageV4Length - (pencsize + 2)):
      break
  # It is possible to make packet size constant by uncommenting this line
  # padsize = 0
  var wosize = pencsize + int(padsize)
  let fullsize = wosize + 2
  if int(padsize) > 0:
    if randomBytes(toa(buffer, PlainAckMessageEIP8Length,
                   int(padsize))) != int(padsize):
      return(RandomError)
  copyMem(addr buffer[0], payload.baseAddr, len(payload))
  if encrypt:
    if len(output) < fullsize:
      return(BufferOverrun)
    bigEndian16(addr output, addr wosize)
    if eciesEncrypt(toa(buffer, 0, len(payload) + int(padsize)),
                    toa(output, 2, wosize), h.remoteHPubkey,
                    toa(output, 0, 2)) != EciesStatus.Success:
      return(EciesError)
    outlen = fullsize
  else:
    let plainsize = len(payload) + int(padsize)
    if len(output) < plainsize:
      return(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], plainsize)
    outlen = plainsize
  result = Success

template authSize*(h: Handshake, encrypt: bool = true): int =
  ## Get number of bytes needed to store AuthMessage.
  if EIP8 in h.flags:
    if encrypt: (AuthMessageMaxEIP8) else: (PlainAuthMessageMaxEIP8)
  else:
    if encrypt: (AuthMessageV4Length) else: (PlainAuthMessageV4Length)

template ackSize*(h: Handshake, encrypt: bool = true): int =
  ## Get number of bytes needed to store AckMessage.
  if EIP8 in h.flags:
    if encrypt: (AckMessageMaxEIP8) else: (PlainAckMessageMaxEIP8)
  else:
    if encrypt: (AckMessageV4Length) else: (PlainAckMessageV4Length)

proc authMessage*(h: var Handshake, pubkey: PublicKey,
                  output: var openarray[byte],
                  outlen: var int, flag: int = 0,
                  encrypt: bool = true): AuthStatus {.inline.} =
  ## Create new AuthMessage for specified `pubkey` and store it inside
  ## of `output`, size of generated AuthMessage will stored in `outlen`.
  if EIP8 in h.flags:
    result = authMessageEIP8(h, pubkey, output, outlen, flag, encrypt)
  else:
    result = authMessagePreEIP8(h, pubkey, output, outlen, flag, encrypt)

proc ackMessage*(h: var Handshake, output: var openarray[byte],
                 outlen: var int, flag: int = 0,
                 encrypt: bool = true): AuthStatus =
  ## Create new AckMessage and store it inside of `output`, size of generated
  ## AckMessage will stored in `outlen`.
  if EIP8 in h.flags:
    result = ackMessageEIP8(h, output, outlen, flag, encrypt)
  else:
    result = ackMessagePreEIP8(h, output, outlen, flag, encrypt)

proc decodeAuthMessageV4(h: var Handshake, m: openarray[byte]): AuthStatus =
  ## Decodes V4 AuthMessage.
  var
    secret: SharedSecret
    buffer: array[PlainAuthMessageV4Length, byte]
    pubkey: PublicKey
  assert(Responder in h.flags)
  if eciesDecrypt(m, buffer, h.host.seckey) != EciesStatus.Success:
    return(EciesError)
  var header = cast[ptr AuthMessageV4](addr buffer[0])
  if recoverPublicKey(header.pubkey.data, pubkey) != EccStatus.Success:
    return(InvalidPubKey)
  if ecdhAgree(h.host.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)
  var xornonce = header.nonce
  xornonce.sxor(secret)
  if recoverSignatureKey(header.signature.data, xornonce,
                         h.remoteEPubkey) != EccStatus.Success:
    return(SignatureError)
  h.initiatorNonce = header.nonce
  h.remoteHPubkey = pubkey
  result = Success

proc decodeAuthMessageEip8(h: var Handshake, m: openarray[byte]): AuthStatus =
  ## Decodes EIP-8 AuthMessage.
  var
    pubkey: PublicKey
    nonce: Nonce
    size: uint16
    secret: SharedSecret
  bigEndian16(addr size, unsafeAddr m[0])
  if 2 + int(size) > len(m):
    return(IncompleteError)
  var buffer = newSeq[byte](eciesDecryptedLength(int(size)))
  if eciesDecrypt(toa(m, 2, int(size)), buffer, h.host.seckey,
                  toa(m, 0, 2)) != EciesStatus.Success:
    return(EciesError)
  try:
    var reader = rlpFromBytes(buffer.toRange())
    if not reader.isList() or reader.listLen() < 4:
      return(InvalidAuth)
    if reader.listElem(0).blobLen != SignatureLength:
      return(InvalidAuth)
    if reader.listElem(1).blobLen != PublicKeyLength:
      return(InvalidAuth)
    if reader.listElem(2).blobLen != KeyLength:
      return(InvalidAuth)
    if reader.listElem(3).blobLen != 1:
      return(InvalidAuth)
    var signatureBr = reader.listElem(0).toBytes()
    var pubkeyBr = reader.listElem(1).toBytes()
    var nonceBr = reader.listElem(2).toBytes()
    var versionBr = reader.listElem(3).toBytes()
    if recoverPublicKey(pubkeyBr.baseAddr, PublicKeyLength,
                        pubkey) != EccStatus.Success:
      return(InvalidPubKey)
    copyMem(addr nonce[0], nonceBr.baseAddr, KeyLength)
    if ecdhAgree(h.host.seckey, pubkey, secret) != EccStatus.Success:
      return(EcdhError)
    var xornonce = nonce
    xornonce.sxor(secret)
    if recoverSignatureKey(signatureBr.baseAddr, SignatureLength,
                           addr xornonce[0],
                           h.remoteEPubkey) != EccStatus.Success:
      return(SignatureError)
    h.initiatorNonce = nonce
    h.remoteHPubkey = pubkey
    h.version = cast[ptr byte](versionBr.baseAddr)[]
    result = Success
  except:
    result = RlpError

proc decodeAckMessageEip8*(h: var Handshake, m: openarray[byte]): AuthStatus =
  ## Decodes EIP-8 AckMessage.
  var size: uint16
  assert(len(m) > 2)
  bigEndian16(addr size, unsafeAddr m[0])
  if 2 + int(size) > len(m):
    return(IncompleteError)
  var buffer = newSeq[byte](eciesDecryptedLength(int(size)))
  if eciesDecrypt(toa(m, 2, int(size)), buffer, h.host.seckey,
                  toa(m, 0, 2)) != EciesStatus.Success:
    return(EciesError)
  try:
    var reader = rlpFromBytes(buffer.toRange())
    if not reader.isList() or reader.listLen() < 3:
      return(InvalidAck)
    if reader.listElem(0).blobLen != PublicKeyLength:
      return(InvalidAck)
    if reader.listElem(1).blobLen != KeyLength:
      return(InvalidAck)
    if reader.listElem(2).blobLen != 1:
      return(InvalidAck)
    let pubkeyBr = reader.listElem(0).toBytes()
    let nonceBr = reader.listElem(1).toBytes()
    let versionBr = reader.listElem(2).toBytes()
    if recoverPublicKey(pubkeyBr.baseAddr, PublicKeyLength,
                        h.remoteEPubkey) != EccStatus.Success:
      return(InvalidPubKey)
    copyMem(addr h.responderNonce[0], nonceBr.baseAddr, KeyLength)
    h.version = cast[ptr byte](versionBr.baseAddr)[]
    result = Success
  except:
    result = RlpError

proc decodeAckMessageV4(h: var Handshake, m: openarray[byte]): AuthStatus =
  ## Decodes V4 AckMessage.
  var
    buffer: array[PlainAckMessageV4Length, byte]
  assert(Initiator in h.flags)
  if eciesDecrypt(m, buffer, h.host.seckey) != EciesStatus.Success:
    return(EciesError)
  var header = cast[ptr AckMessageV4](addr buffer[0])
  if recoverPublicKey(header.pubkey.data, h.remoteEPubkey) != EccStatus.Success:
    return(InvalidPubKey)
  h.responderNonce = header.nonce
  result = Success

proc decodeAuthMessage*(h: var Handshake, input: openarray[byte]): AuthStatus =
  ## Decodes AuthMessage from `input`.
  if len(input) < AuthMessageV4Length:
    result = IncompleteError
  elif len(input) == AuthMessageV4Length:
    let res = h.decodeAuthMessageV4(input)
    if res != Success:
      if h.decodeAuthMessageEip8(input) != Success:
        result = res
      else:
        h.flags.incl(EIP8)
        result = Success
    else:
      result = Success
  else:
    result = h.decodeAuthMessageEip8(input)
    if result == Success:
      h.flags.incl(EIP8)

proc decodeAckMessage*(h: var Handshake, input: openarray[byte]): AuthStatus =
  ## Decodes AckMessage from `input`.
  if len(input) < AckMessageV4Length:
    return(IncompleteError)
  elif len(input) == AckMessageV4Length:
    let res = h.decodeAckMessageV4(input)
    if res != Success:
      if h.decodeAckMessageEip8(input) != Success:
        result = res
      else:
        h.flags.incl(EIP8)
        result = Success
    else:
      result = Success
  else:
    result = h.decodeAckMessageEip8(input)
    if result == Success:
      h.flags.incl(EIP8)

proc getSecrets*(h: Handshake, authmsg: openarray[byte],
                 ackmsg: openarray[byte],
                 secret: var ConnectionSecret): AuthStatus =
  ## Derive secrets from handshake `h` using encrypted AuthMessage `authmsg` and
  ## encrypted AckMessage `ackmsg`.
  var
    shsec: SharedSecret
    ctx0: keccak256
    ctx1: keccak256
    mac1: MDigest[256]
    mac2: MDigest[256]
    xornonce: Nonce

  # ecdhe-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
  if ecdhAgree(h.ephemeral.seckey, h.remoteEPubkey, shsec) != EccStatus.Success:
    return(EcdhError)

  # shared-secret = keccak(ecdhe-secret || keccak(nonce || initiator-nonce))
  ctx0.init()
  ctx1.init()
  ctx1.update(h.responderNonce)
  ctx1.update(h.initiatorNonce)
  mac1 = ctx1.finish()
  ctx1.clear()
  ctx0.update(shsec)
  ctx0.update(mac1.data)
  mac1 = ctx0.finish()

  # aes-secret = keccak(ecdhe-secret || shared-secret)
  ctx0.init()
  ctx0.update(shsec)
  ctx0.update(mac1.data)
  mac1 = ctx0.finish()

  # mac-secret = keccak(ecdhe-secret || aes-secret)
  ctx0.init()
  ctx0.update(shsec)
  ctx0.update(mac1.data)
  secret.aesKey = mac1.data
  mac1 = ctx0.finish()
  secret.macKey = mac1.data

  burnMem(shsec)
  # egress-mac = keccak256(mac-secret ^ recipient-nonce || auth-sent-init)
  xornonce = mac1.data
  xornonce.sxor(h.responderNonce)
  ctx0.init()
  ctx0.update(xornonce)
  ctx0.update(authmsg)
  mac1 = ctx0.finish()

  # ingress-mac = keccak256(mac-secret ^ initiator-nonce || auth-recvd-ack)
  xornonce = secret.macKey
  xornonce.sxor(h.initiatorNonce)
  ctx0.init()
  ctx0.update(xornonce)
  ctx0.update(ackmsg)
  mac2 = ctx0.finish()

  ctx0.init() # clean keccak256 context
  zeroMem(addr xornonce[0], sizeof(Nonce)) # clean xornonce

  if Initiator in h.flags:
    secret.egressMac = mac1.data
    secret.ingressMac = mac2.data
  else:
    secret.ingressMac = mac1.data
    secret.egressMac = mac2.data

  burnMem(mac1)
  burnMem(mac2)
  result = Success
