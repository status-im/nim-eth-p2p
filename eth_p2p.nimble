mode = ScriptMode.Verbose

packageName   = "eth_p2p"
version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum P2P library"
license       = "MIT"
skipDirs      = @["tests", "Nim"]

requires "nim > 0.18.0",
         "rlp >= 1.0.1",
         "nimcrypto",
         "secp256k1 >= 0.1.0",
         "eth_keys",
         "ranges",
         "stint",
         "byteutils",
         "chronicles",
         "asyncdispatch2",
         "eth_common",
         "package_visible_types",
         "https://github.com/jangko/snappy"

proc runTest(name: string, defs = "", lang = "c") =
  exec "nim " & lang & " " & defs & " -d:testing --experimental:ForLoopMacros -r tests/" & name

task test, "Runs the test suite":
  runTest "testenode"
  runTest "tdiscovery"
  runTest "tserver"
  runTest "tserver", "-d:useSnappy"
  runTest "all_tests"
