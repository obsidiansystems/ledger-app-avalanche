{ runTest ? true, gitDescribe ? "TEST-dirty" }:
let
  ledger-app = import ./. { inherit runTest gitDescribe; };
in rec {
  analysis-nanos = ledger-app.clangAnalysis.s.wallet;
  release-nanos = ledger-app.nano.s.release.all;
  release-nanox = ledger-app.nano.x.release.all;
  debug-build = (import ./. { debug = true; inherit runTest gitDescribe; }).nano.s.release.all;
  usbtool = import ./nix/usbtool.nix {};
  hashes = ledger-app.pkgs.writeScript "hashes" ''
     PATH=${ledger-app.pkgs.coreutils}:$PATH
     MD5=$(md5sum -b ${release-nanos} | awk '{print $1;}')
     SHA256=$(sha256sum -b ${release-nanos} | awk '{print $1;}')
     SHA512=$(sha512sum -b ${release-nanos} | awk '{print $1;}')
     echo "MD5 | $MD5"
     echo "SHA256 | $SHA256"
     echo "SHA512 | $SHA512"
   '';
}
