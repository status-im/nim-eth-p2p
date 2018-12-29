mode = ScriptMode.Verbose

packageName   = "stratus"
version       = "0.0.0.1"
author        = "Status Research & Development GmbH"
description   = "Fun with nimbus"
license       = "MIT"

bin           = @["stratus"]

requires "eth_p2p",
         "nimqml",
         "cligen 0.9.18"
