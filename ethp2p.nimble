mode = ScriptMode.Verbose

packageName   = "ethp2p"
version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum P2P library"
license       = "MIT"
skipDirs      = @["tests", "Nim"]

requires "nim > 0.18.0", "https://github.com/status-im/nim-rlp >= 1.0.1", "https://github.com/cheatfate/nimcrypto >= 0.1.0", "https://github.com/status-im/nim-secp256k1 >= 0.1.0"

task tests, "Runs the test suite":
  exec "nim c -r tests/testecc"
  exec "nim c -r tests/testecies"
  exec "nim c -r tests/testauth"
