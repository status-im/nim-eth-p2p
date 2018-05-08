mode = ScriptMode.Verbose

packageName   = "ethp2p"
version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum P2P library"
license       = "MIT"
skipDirs      = @["tests", "Nim"]

requires "nim > 0.18.0",
         "rlp >= 1.0.1",
         "https://github.com/cheatfate/nimcrypto",
         "secp256k1 >= 0.1.0",
         "eth_keys",
         "ranges",
         "https://github.com/status-im/nim-stint",
         "https://github.com/status-im/nim-byteutils"

proc runTest(name: string, lang = "c") = exec "nim " & lang & " -r tests/" & name

task test, "Runs the test suite":
  runTest "testecies"
  runTest "testauth"
  runTest "testcrypt"
  runTest "testenode"
  runTest "tdiscovery"
