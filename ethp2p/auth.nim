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
import hexdump

const
  SupportedRlpxVersion* = 4
  # REVIEW: If these messages have fixed lenghts, they will be
  # better described by an object type (see my similar comments
  # in the ecies module.
  PlainAuthMessageLength* = 194
  PlainAuthAckMessageLength* = 97
  AuthMessageLength* = 307
  AuthAckMessageLength* = 210

type
  HandshakeFlag* = enum
    Initiator,      ## `Handshake` owner is connection initiator
    Responder,      ## `Handshake` owner is connection responder
    Eip8            ## Flag indicates that EIP-8 handshake is used

  AuthStatus* = enum
    Success,        ## Operation was successful
    RandomError,    ## Could not obtain random data
    EcdhError,      ## ECDH shared secret could not be calculated
    SignatureError, ## Signature could not be obtained
    EciesError,     ## ECIES encryption/decryption error
    InvalidPubKey,  ## Invalid public key
    InvalidAuth,    ## Invalid Authentication message
    InvalidAck,     ## Invalid Authentication ACK message
    RlpError,       ## Error while decoding RLP stream
    IncompleteError ## Data incomplete error

  Handshake* = object
    version: uint8
    flags: set[HandshakeFlag]
    host*: KeyPair
    ephemeral*: KeyPair
    remoteHPubkey*: PublicKey
    remoteEPubkey*: PublicKey
    initiatorNonce*: Nonce
    responderNonce*: Nonce

  ConnectionSecret* = object
    # REVIEW: it would be nice if Nimcrypto defines distinct or
    # alias types such as `aes256.key` instead of having to spell
    # out the full array type everywhere.
    aesKey*: array[aes256.sizeKey, byte]
    macKey*: array[KeyLength, byte]
    egressMac*: array[keccak256.sizeDigest, byte]
    ingressMac*: array[keccak256.sizeDigest, byte]

  PlainAuthMessage* = array[PlainAuthMessageLength, byte]
  PlainAuthAckMessage* = array[PlainAuthAckMessageLength, byte]
  AuthMessage* = array[AuthMessageLength, byte]
  AuthAckMessage* = array[AuthAckMessageLength, byte]

  AuthException* = object of Exception

proc sxor[T](a: var openarray[T], b: openarray[T]) =
  assert(len(a) == len(b))
  for i in 0 ..< len(a):
    a[i] = a[i] xor b[i]

proc empty[T](v: openarray[T]): bool =
  var r: T
  for item in v:
    r = r + item
  result = (r == T(0))

proc move[T](dst: var openarray[T], src: openarray[T],
             dstx: int = 0, dsty: int = -1, srcx: int = 0, srcy: int = -1) =
  let sx = if srcx < 0: (len(src) + srcx) else: srcx
  let sy = if srcy < 0: (len(src) + srcy) else: srcy
  let dx = if dstx < 0: (len(dst) + dstx) else: dstx
  let dy = if dsty < 0: (len(dst) + dsty) else: dsty
  assert(sy - sx == dy - dx)
  moveMem(addr dst[dstx], unsafeAddr src[srcx], (dy - dx + 1) * sizeof(T))

proc newHandshake*(flags: set[HandshakeFlag] = {Initiator}): Handshake =
  var p: ptr byte
  result.flags = flags
  result.ephemeral = newKeyPair()

  if Initiator in flags:
    p = addr result.initiatorNonce[0]
  else:
    p = addr result.responderNonce[0]

  if randomBytes(p, KeyLength) != KeyLength:
    raise newException(AuthException, "Could not obtain random data!")

proc authMessage*(h: var Handshake,
                  pubkey: PublicKey,
                  output: var PlainAuthMessage): AuthStatus =
  ## Create plain preEIP8 authentication message.
  var secret: SharedSecret
  var signature: Signature
  var flag = byte(0x00)

  if ecdhAgree(h.host.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)

  if h.initiatorNonce.empty():
    if randomBytes(addr h.initiatorNonce[0], KeyLength) != KeyLength:
      return(RandomError)

  var xornonce = h.initiatorNonce
  xornonce.sxor(secret)

  if signMessage(h.ephemeral.seckey, xornonce, signature) != EccStatus.Success:
    return(SignatureError)

  copyMem(addr h.remoteHPubkey, unsafeAddr pubkey, sizeof(PublicKey))

  move(output, signature.getRaw().data, 0, 64)
  move(output, keccak256.digest(h.ephemeral.pubkey.getRaw().data).data, 65, 96)
  move(output, h.host.pubkey.getRaw().data, 97, 160)
  move(output, h.initiatorNonce, 161, 192)
  output[193] = flag

proc authAckMessage*(h: var Handshake,
                     output: var PlainAuthAckMessage): AuthStatus =
  if EIP8 in h.flags:
    discard
  else:
    move(output, h.ephemeral.pubkey.getRaw().data, 0, 63)
    move(output, h.responderNonce, 64, 95)
    output[96] = byte(0x00)

proc encryptAuthMessage*(input: ptr byte, inputlen: int,
                         output: ptr byte, outputlen: int,
                         pubkey: PublicKey, shmac: ptr byte = nil,
                         shlen: int = 0): AuthStatus =
  result = Success
  if eciesEncrypt(input, output, inputlen, outputlen,
                  pubkey, shmac, shlen) != EciesStatus.Success:
    result = EciesError

proc encryptAuthMessage*(input: PlainAuthMessage,
                         output: var AuthMessage,
                         pubkey: PublicKey): AuthStatus =
  result = Success
  result = encryptAuthMessage(unsafeAddr input[0], PlainAuthMessageLength,
                              addr output[0], AuthMessageLength, pubkey)

proc decryptAuthMessage*(input: ptr byte, inputlen: int,
                         output: ptr byte, outputlen: int,
                         seckey: PrivateKey, shmac: ptr byte = nil,
                         shlen: int = 0): AuthStatus =
  result = Success
  if eciesDecrypt(input, output, inputlen, outputlen,
                  seckey, shmac, shlen) != EciesStatus.Success:
    result = EciesError

proc decryptAuthMessage*(input: AuthMessage, output: var PlainAuthMessage,
                         seckey: PrivateKey): AuthStatus =
  result = decryptAuthMessage(unsafeAddr input[0], AuthMessageLength,
                              addr output[0], PlainAuthMessageLength,
                              seckey)

proc encryptAuthAckMessage*(input: ptr byte, inputlen: int,
                            output: ptr byte, outputlen: int,
                            pubkey: PublicKey, shmac: ptr byte = nil,
                            shlen: int = 0): AuthStatus =
  result = Success
  if eciesEncrypt(input, output, inputlen, outputlen,
                  pubkey, shmac, shlen) != EciesStatus.Success:
    result = EciesError

proc encryptAuthAckMessage*(input: PlainAuthAckMessage,
                            output: var AuthAckMessage,
                            pubkey: PublicKey): AuthStatus =
  result = encryptAuthAckMessage(unsafeAddr input[0], PlainAuthAckMessageLength,
                                 addr output[0], AuthAckMessageLength,
                                 pubkey)

proc decryptAuthAckMessage*(input: ptr byte, inputlen: int,
                            output: ptr byte, outputlen: int,
                            seckey: PrivateKey, shmac: ptr byte = nil,
                            shlen: int = 0): AuthStatus =
  result = Success
  if eciesDecrypt(input, output, inputlen, outputlen,
                  seckey, shmac, shlen) != EciesStatus.Success:
    result = EciesError

proc decryptAuthAckMessage*(input: AuthAckMessage,
                            output: var PlainAuthAckMessage,
                            seckey: PrivateKey): AuthStatus =
  result = decryptAuthAckMessage(unsafeAddr input[0], AuthAckMessageLength,
                                 addr output[0], PlainAuthAckMessageLength,
                                 seckey)

proc decodePlainAuthMessage(h: var Handshake, m: PlainAuthMessage): AuthStatus =
  var secret: SharedSecret
  var nonce: array[32, byte]
  var pubkey: PublicKey

  copyMem(addr nonce[0], unsafeAddr m[161], KeyLength)
  if recoverPublicKey(unsafeAddr m[97], sizeof(PublicKey),
                      pubkey) != EccStatus.Success:
    return(InvalidPubKey)

  if ecdhAgree(h.host.seckey, pubkey, secret) != EccStatus.Success:
    return(EcdhError)

  var xornonce = nonce
  xornonce.sxor(secret)

  if recoverSignatureKey(unsafeAddr m[0], SignatureLength, addr xornonce[0],
                         h.remoteEPubkey) != EccStatus.Success:
    return(SignatureError)

  h.initiatorNonce = nonce
  h.remoteHPubkey = pubkey
  result = Success

proc decodePlainAuthAckMessage*(h: var Handshake,
                                m: PlainAuthAckMessage): AuthStatus =
  if recoverPublicKey(m, h.remoteEPubkey, 0, 63) != EccStatus.Success:
    return(InvalidPubKey)

  h.responderNonce[0..31] = m[64..95]
  result = Success

proc getSecrets*(h: var Handshake,
                 msg: ptr byte, msglen: int,
                 ack: ptr byte, acklen: int,
                 secret: var ConnectionSecret): AuthStatus =

  var
    shsec: SharedSecret
    ctx0: keccak256
    ctx1: keccak256
    digest: array[keccak256.sizeDigest, byte]
    mac1: array[keccak256.sizeDigest, byte]
    mac2: array[keccak256.sizeDigest, byte]
    xornonce: Nonce

  # ecdhe-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
  if ecdhAgree(h.ephemeral.seckey, h.remoteEPubkey, shsec) != EccStatus.Success:
    return(EcdhError)

  # shared-secret = keccak(ecdhe-secret || keccak(nonce || initiator-nonce))
  ctx0.init()
  ctx1.init()
  ctx1.update(addr h.responderNonce[0], uint(len(h.responderNonce)))
  ctx1.update(addr h.initiatorNonce[0], uint(len(h.initiatorNonce)))
  digest = ctx1.finish().data

  ctx1.init() # clean keccak256 context
  ctx0.update(addr shsec[0], uint(sizeof(SharedSecret)))
  ctx0.update(addr digest[0], uint(keccak256.sizeDigest))
  digest = ctx0.finish().data

  # aes-secret = keccak(ecdhe-secret || shared-secret)
  ctx0.init()
  ctx0.update(addr shsec[0], uint(sizeof(SharedSecret)))
  ctx0.update(addr digest[0], uint(keccak256.sizeDigest))
  secret.aesKey = ctx0.finish().data

  # mac-secret = keccak(ecdhe-secret || aes-secret)
  ctx0.init()
  ctx0.update(addr shsec[0], uint(sizeof(SharedSecret)))
  ctx0.update(addr secret.aesKey[0], uint(keccak256.sizeDigest))
  secret.macKey = ctx0.finish().data

  zeroMem(addr shsec[0], sizeof(SharedSecret)) # clean ecdhe-secret

  # egress-mac = keccak256(mac-secret ^ recipient-nonce || auth-sent-init)
  xornonce = secret.macKey
  xornonce.sxor(h.responderNonce)
  ctx0.init()
  ctx0.update(addr xornonce[0], uint(sizeof(Nonce)))
  ctx0.update(msg, uint(msglen))
  mac1 = ctx0.finish().data

  # ingress-mac = keccak256(mac-secret ^ initiator-nonce || auth-recvd-ack)
  xornonce = secret.macKey
  xornonce.sxor(h.initiatorNonce)
  ctx0.init()
  ctx0.update(addr xornonce[0], uint(sizeof(Nonce)))
  ctx0.update(ack, uint(acklen))
  mac2 = ctx0.finish().data

  ctx0.init() # clean keccak256 context
  zeroMem(addr xornonce[0], sizeof(Nonce)) # clean xornonce

  if Initiator in h.flags:
    secret.egressMac = mac1
    secret.ingressMac = mac2
  else:
    secret.ingressMac = mac1
    secret.egressMac = mac2

  zeroMem(addr mac1[0], keccak256.sizeDigest) # clean temporary mac1
  zeroMem(addr mac2[0], keccak256.sizeDigest) # clean temporary mac2

  result = Success

proc getSecrets*(h: var Handshake, msg: AuthMessage, ack: AuthAckMessage,
                 secret: var ConnectionSecret): AuthStatus =
  result = getSecrets(h, unsafeAddr msg[0], AuthMessageLength,
                      unsafeAddr ack[0], AuthAckMessageLength,
                      secret)

proc decodeAuthEip8Message*(h: var Handshake, msg: ptr byte,
                            msglen: int): AuthStatus =
  var
    pubkey: PublicKey
    nonce: Nonce
    size: uint16
    secret: SharedSecret
  if msglen < 2:
    return(InvalidAuth)
  bigEndian16(addr size, msg)

  if (2 + int(size)) > msglen:
    return(InvalidAuth)

  # Maximum `size` value is 65535 bytes
  var outlen = eciesDecryptedLength(int(size))
  var output = newSeq[byte](outlen)
  var input = cast[ptr UncheckedArray[byte]](msg)
  if decryptAuthMessage(addr input[2], int(size), addr output[0],
                        outlen, h.host.seckey,
                        addr input[0], 2) != Success:
    return(EciesError)

  try:
    var reader = rlpFromBytes(output.toRange())
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
    return(RlpError)

proc decodeAuthAckEip8Message(h: var Handshake, msg: ptr byte,
                              msglen: int): AuthStatus =
  var size: uint16
  if msglen < 2:
    return(IncompleteError)
  bigEndian16(addr size, msg)

  if (2 + int(size)) > msglen:
    return(IncompleteError)

  # Maximum `size` value is 65535 bytes
  var outlen = eciesDecryptedLength(int(size))
  var output = newSeq[byte](outlen)
  var input = cast[ptr UncheckedArray[byte]](msg)
  if decryptAuthMessage(addr input[2], int(size), addr output[0],
                        outlen, h.host.seckey,
                        addr input[0], 2) != Success:
    return(EciesError)

  try:
    var reader = rlpFromBytes(output.toRange())
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
    return(RlpError)

proc decodeAuthMessage*(h: var Handshake, msg: ptr byte,
                        msglen: int): AuthStatus =
  if msglen < AuthMessageLength:
    return(IncompleteError)
  elif msglen == AuthMessageLength:
    # Decoding plain authentication message
    var plain: PlainAuthMessage
    result = decryptAuthMessage(msg, msglen, addr plain[0],
                                sizeof(PlainAuthMessage), h.host.seckey)
    if result == Success:
      result = decodePlainAuthMessage(h, plain)
  else:
    # Decoding EIP-8 authentication message
    result = decodeAuthEip8Message(h, msg, msglen)
    if result == Success:
      h.flags.incl(EIP8)

proc decodeAckMessage*(h: var Handshake, msg: ptr byte,
                       msglen: int): AuthStatus =
  if msglen < AuthAckMessageLength:
    return(IncompleteError)
  elif msglen == AuthAckMessageLength:
    # Decoding plain authentication ACK message
    var plain: PlainAuthAckMessage
    result = decryptAuthAckMessage(msg, msglen, addr plain[0],
                                   PlainAuthAckMessageLength,
                                   h.host.seckey)
    if result == Success:
      result = decodePlainAuthAckMessage(h, plain)
  else:
    # Decoding EIP-8 ACK authentication message
    result = decodeAuthAckEip8Message(h, msg, msglen)

proc decodeAuthMessage*(h: var Handshake, msg: openarray[byte]): AuthStatus =
  result = decodeAuthMessage(h, unsafeAddr msg[0], len(msg))

proc decodeAckMessage*(h: var Handshake, msg: openarray[byte]): AuthStatus =
  result = decodeAckMessage(h, unsafeAddr msg[0], len(msg))
