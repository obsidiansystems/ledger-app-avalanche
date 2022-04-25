{ runTest ? false, gitDescribe ? "TEST-dirty" }:
/*
The above should be `runTest ? true`, but ledger recently introduced a change that causes
eth.signTransaction to connect to cdn.ledger.com when contract data is attached.
This breaks tests on release. So, to allow release to run, skip tests for now.
Reenable ASAP.
*/
let
  ledger-app = import ./. {
    localSystem = { system = "x86_64-linux"; };
    inherit runTest gitDescribe;
  };
in rec {
  analysis-nanos = ledger-app.clangAnalysis.s.wallet;
  release-nanos = ledger-app.nano.s.release.all;
  release-nanox = ledger-app.nano.x.release.all;
  debug-build = (import ./. { debug = true; inherit runTest gitDescribe; }).nano.s.release.all;
  inherit (ledger-app) usbtool;
  ledger-blue = (import ./nix/ledgerblue.nix {}).withLedgerblue;
  release-notes = ledger-app.pkgs.writeScript "release-notes" ''
     PATH=${ledger-app.pkgs.coreutils}:$PATH
     MD5=$(md5sum -b ${release-nanos} | awk '{print $1;}')
     SHA256=$(sha256sum -b ${release-nanos} | awk '{print $1;}')
     SHA512=$(sha512sum -b ${release-nanos} | awk '{print $1;}')
     CODE_IDENTIFIER=$(tar xfO ${release-nanos} ledger-app-avalanche-s/code-identifier.txt)

     echo "MD5 | $MD5"
     echo "SHA256 | $SHA256"
     echo "SHA512 | $SHA512"
     echo
     echo "Code Identifier: $CODE_IDENTIFIER"
   '';
}
