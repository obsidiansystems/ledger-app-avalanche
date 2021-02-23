{ pkgs ? import ./nixpkgs {} }:

# Doesn't seem to work with instructions in https://ledger.readthedocs.io/en/latest/userspace/debugging.html
# The 'log' command is not present in the github repo, only the vendored version provided in the link above
pkgs.stdenv.mkDerivation {
  name = "usbtool";
  src = pkgs.fetchFromGitHub {
    owner = "obdev";
    repo = "v-usb";
    rev = "9a42d205eb60faca494ff4eabce8d59f0ec0fc7f";
    sha256 = "009zm7dl69fcj7jachlrxafi8scggwq9dsbqcshf3wk34pragjhw";
  };
  preBuild = ''
    cd examples/usbtool
    ./make-files.sh
  '';
  buildInputs = [ pkgs.libusb ];
  installPhase = ''
    install -D usbtool $out/bin/usbtool
    install -D Readme.txt $out/share/doc/usbtool/Readme.txt
  '';
}
