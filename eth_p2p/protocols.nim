#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import algorithm, hashes

type
  ECap* = distinct int
    ## Internal representation of Ethereum Capability

  CapName* = array[3, char]
    ## Internal representation of Ethereum Capability protocol name

  RlpCap* = object
    ## RLP presentation of Ethereum Capability
    name*: CapName
    version*: int

  EPeerCap* = object
    ## Synchronized Ethereum Capability
    cap*: ECap
    offset*: int
    index*: int

  ECapList* = seq[ECap]
    ## Ethereum Capabilities list object
  RlpCapList* = seq[RlpCap]
    ## RLP serialized list of Ethereum Capabilities
  EPeerCapList* = seq[EPeerCap]
    ## Synchronized list of Ethereum Capabilities

proc newECapList*(): ECapList =
  ## Create new empty Ethereum Capabilities list.
  result = newSeq[ECap]()

proc initECap*(name: string, version: int): ECap =
  ## Create new Ethereum Capability using protocol name ``name`` and protocol
  ## version ``version``.
  assert(len(name) >= 3)
  assert(version >= 0 and version <= 255)
  result = ECap((int(name[0]) shl 24) or (int(name[1]) shl 16) or
                 (int(name[2]) shl 8) or (int(version) and 0xFF))

proc initECap*(rcap: RlpCap): ECap =
  ## Create new Ethereum Capability using RLP serialized capability.
  assert(rcap.version >= 0 and rcap.version <= 255)
  result = ECap((int(rcap.name[0]) shl 24) or (int(rcap.name[1]) shl 16) or
                  (int(rcap.name[2]) shl 8) or (int(rcap.version) and 0xFF))

proc initRCap*(ecap: ECap): RlpCap =
  ## Create RLP serialized Ethereum Capability from internal representation of
  ## Ethereum Capability ``ecap``.
  result.name[0] = chr((int(ecap) shr 24) and 0xFF)
  result.name[1] = chr((int(ecap) shr 16) and 0xFF)
  result.name[2] = chr((int(ecap) shr 8) and 0xFF)
  result.version = int(ecap) and 0xFF

proc hash*(ecap: ECap): Hash {.inline.} =
  ## Calculate ``Hash`` for Ethereum Capability ``ecap``.
  result = Hash(ecap)

proc `$`*(ecap: ECap): string =
  ## Get string representation of Ethereum Capability ``ecap``.
  result = newStringOfCap(8)
  result.setLen(4)
  result[3] = '/'
  result[2] = chr((int(ecap) shr 8) and 0xFF)
  result[1] = chr((int(ecap) shr 16) and 0xFF)
  result[0] = chr((int(ecap) shr 24) and 0xFF)
  result.add($(int(ecap) and 0xFF))

proc `$`*(rcap: RlpCap): string =
  ## Get string representation of RLP serialized Ethereum Capability ``rcap``.
  result = newStringOfCap(8)
  result.setLen(4)
  result[3] = '/'
  result[2] = rcap.name[2]
  result[1] = rcap.name[1]
  result[0] = rcap.name[0]
  result.add($rcap.version)

proc cmpProto*(ecap1, ecap2: ECap): int =
  ## Compare protocols of Ethereum Capabilities ``ecap1`` and ``ecap2``.
  result = ((int(ecap1) shr 8) and 0xFFFFFF) -
             ((int(ecap2) shr 8) and 0xFFFFFF)

proc cmpVersion*(ecap1, ecap2: ECap): int =
  ## Compare versions of Ethereum Capabilities ``ecap1`` and ``ecap2``.
  result = (int(ecap1) and 0xFF) - (int(ecap2) and 0xFF)

proc version*(ecap: ECap): int =
  ## Get version of Ethereum Capability ``ecap`` as integer.
  result = (int(ecap) and 0xFF)

proc protocol*(ecap: ECap): string =
  ## Get protocol of Ethereum Capability ``ecap`` as string.
  result = newString(3)
  result[0] = chr((int(ecap) shr 24) and 0xFF)
  result[1] = chr((int(ecap) shr 16) and 0xFF)
  result[2] = chr((int(ecap) shr 8) and 0xFF)

proc protocol*(epcap: EPeerCap): string {.inline.} =
  ## Get protocol of Ethereum Capability ``epcap`` as string.
  result = epcap.cap.protocol()

proc version*(epcap: EPeerCap): int {.inline.} =
  ## Get version of Ethereum Capability ``ecap`` as integer.
  result = epcap.cap.version()

proc `==`*(x: ECap, y: ECap): bool {.borrow.}
  ## Compare Ethereum Capabilities ``x`` and ``y``.

type
  EProtocol* = object
    cap*: ECap
    length*: int

const
  EthereumProtocols* = [
    EProtocol(cap: initECap("eth", 61), length: 9),
    EProtocol(cap: initECap("eth", 62), length: 8),
    EProtocol(cap: initECap("eth", 63), length: 16),
    EProtocol(cap: initECap("les", 1), length: 15),
    EProtocol(cap: initECap("les", 2), length: 21)
  ]

proc protoLength*(cap: ECap): int =
  ## Get number of commands for Ethereum Capability ``cap``.
  for item in EthereumProtocols:
    if item.cap == cap:
      result = item.length
      break

proc cmp*(x, y: ECap): int =
  ## Comparison function for sorting Ethereum Capabilities.
  if x == y: return 0
  if int(x) < int(y): return -1
  return 1

proc sync*(secap, ecap: ECapList): EPeerCapList =
  ## Synchronize local and remote lists of Ethereum Capabilities, and calculate
  ## protocol commands' offsets.
  ##
  ## Please note, that ``secap`` list must be sorted!
  result = newSeq[EPeerCap]()
  var curindex = 0
  for cap1 in secap:
    for cap2 in ecap:
      if cap1 == cap2:
        if len(result) == 0:
          # first added protocol has 0x10 offset
          result.add(EPeerCap(cap: cap1, offset: 16, index: curindex))
          inc(curindex)
        else:
          let prev = result[^1]
          if cmpProto(prev.cap, cap1) == 0:
            if cmpVersion(prev.cap, cap1) < 0:
              # replacing same protocol with most recent version
              result[^1] = EPeerCap(cap: cap1, offset: prev.offset)
          else:
            # adding new protocol with offset
            let offset = prev.offset + protoLength(prev.cap)
            result.add(EPeerCap(cap: cap1, offset: offset, index: curindex))
            inc(curindex)

proc register*(lcap: var ECapList, cap: ECap) =
  ## Registers Ethereum Capability ``cap`` in list ``lcap``.
  ##
  ## Procedure keeps list ``lcap`` sorted.
  if len(lcap) == 0:
    lcap.add(cap)
  else:
    for item in lcap:
      if item == cap:
        return
    lcap.add(cap)
    sort(lcap, cmp)

proc register*(lcap: var ECapList, caps: openarray[ECap]) =
  ## Registers array of Ethereum Capabilities ``caps`` in list ``lcap``.
  ##
  ## Procedure keeps ``lcap`` sorted.
  for item in caps:
    lcap.register(item)

proc unregister*(lcap: var ECapList, cap: ECap) =
  ## Unregister Ethereum Capability ``cap`` from list ``lcap``.
  ##
  ## Procedure keeps list ``lcap`` sorted.
  var scap: seq[ECap]
  for item in lcap:
    if item != cap:
      scap.add(item)
  if len(scap) != len(lcap):
    shallowCopy(lcap, scap)

proc unregister*(lcap: var ECapList, caps: openarray[ECap]) =
  ## Unregister array of Ethereum Capabilities from list ``lcap``.
  ##
  ## Procedure keeps list ``lcap`` sorted.
  for item in caps:
    lcap.unregister(item)

proc newECapList*(caps: openarray[ECap]): ECapList =
  ## Create new Ethereum Capabilities list and populate it with capabilities
  ## from ``caps``.
  result = newSeq[ECap]()
  result.register(caps)

proc newECapList*(cap: ECap): ECapList =
  ## Create new Ethereum Capabilities list and register capability ``cap``
  ## in it.
  result = newSeq[ECap]()
  result.register(cap)

proc `$`*(lcap: ECapList): string =
  ## Get string representation of Ethereum Capabilities list ``lcap``.
  result = ""
  for item in lcap:
    if len(result) > 0:
      result.add(", ")
      result.add($item)
    else:
      result.add($item)

proc `$`*(pcap: EPeerCapList): string =
  ## Get string representation of synchronized remote peer capabilities
  ## ``pcap``.
  result = ""
  for item in pcap:
    if len(result) > 0:
      result.add(", ")
      result.add($item.cap)
      result.add(" (")
      result.add($item.offset)
      result.add("/")
      result.add($item.index)
      result.add(")")
    else:
      result.add($item.cap)
      result.add(" (")
      result.add($item.offset)
      result.add(" / ")
      result.add($item.index)
      result.add(")")

proc `$`*(rcap: RlpCapList): string =
  ## Get string representation of RLP serialized Ethereum Capabilities list.
  result = ""
  for item in rcap:
    if len(result) > 0:
      result.add(", ")
      result.add($item)
    else:
      result.add($item)

proc cmdId*(epcap: EPeerCap, cmdid: int): int {.inline.} =
  ## Get actual command id of command with ``cmdid`` using data from
  ## synchronized peer capability ``epcap``.
  result = cmdid + epcap.offset

proc cmdId*(pcap: EPeerCapList, proto: string, cmdid: int): int =
  ## Get actual command id from protocol with name ``proto`` and list of
  ## synchronized peer capabilities ``pcap``.
  result = cmdid
  var cap = initECap(proto, 0)
  for item in pcap:
    if cmpProto(item.cap, cap) == 0:
      result += item.offset
      break

proc protoId*(epcap: EPeerCap, cmdid: int): int {.inline.} =
  ## Get sub-protocol specific ``message id`` (zero based) from peer's cmd id.
  result = cmdid - epcap.offset

proc fromRlp*(lrlpcap: openarray[RlpCap]): ECapList =
  ## Convert list of RLP serialized Ethereum Capabilities to list of Ethereum
  ## Capabilities.
  result = newECapList()
  for item in lrlpcap:
    result.register(initECap(item))

proc toRlp*(lcap: openarray[ECap]): RlpCapList =
  ## Convert list of Ethereum Capabilities ``lcap`` to list of RLP serialized
  ## Ethereum Capabilities.
  result = newSeq[RlpCap]()
  for item in lcap:
    result.add(initRCap(item))

when isMainModule:
  var lcaplist = newECapList()
  var rcaplist = newECapList()

  var a = initECap("eth", 61)
  var b = initECap("eth", 62)
  var c = initECap("eth", 63)
  var d = initECap("les", 1)
  var e = initECap("les", 2)
  var f = initECap("par", 1)
  var g = initECap("par", 2)

  lcaplist.register([a, b, c, d])
  rcaplist.register([e, d, d, c, b, a, f, g])

  echo "local ", lcaplist
  echo "remote ", rcaplist

  echo sync(lcaplist, rcaplist)
