{  ledger-platform ? import ../nix/dep/ledger-platform {}, ... }:
rec {
  withLedgerblue = (ledger-platform.pkgs.python3.withPackages (ps: with ps; [
    ecpy hidapi pycrypto python-u2flib-host requests ledgerblue pillow pkgs.hidapi protobuf
  ]));
  shell = withLedgerblue.env;
}
