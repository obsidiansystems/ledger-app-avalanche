{ pkgs ? import (import ../nix/dep/alamgu/thunk.nix + "/dep/nixpkgs") {}
, nodejs ? pkgs.nodejs
}:

let
  inherit (pkgs) lib;
  yarn2nix = import deps/yarn2nix { inherit pkgs; };
  getThunkSrc = (import ./deps/reflex-platform { }).hackGet;
  npmDepsNix = pkgs.runCommand "npm-deps.nix" {} ''
    ${yarn2nix}/bin/yarn2nix --offline \
      <(sed -e '/hw-app-avalanche/,/^$/d' ${./yarn.lock}) \
      > $out
  '';
  npmPackageNix = pkgs.runCommand "npm-package.nix" {} ''
    # We sed hw-app-avalanche to a constant here, so that the package.json can be whatever; we're overriding it anyways.
    ${yarn2nix}/bin/yarn2nix --template \
      <(sed 's/hw-app-avalanche".*$/hw-app-avalanche": "0.1.0",/' ${./package.json}) \
      > $out
  '';
  nixLib = yarn2nix.nixLib;

  localOverrides = self: super:
      let
        registries = {
          yarn = n: v: "https://registry.yarnpkg.com/${n}/-/${n}-${v}.tgz";
        };
        y = registries.yarn;
        s = self;
      in {
        "bcrypto@5.3.0" = super._buildNodePackage {
          key="bcrypto";
          version="5.3.0";
          src = pkgs.fetchurl {
            url = y "bcrypto" "5.3.0";
            sha1 = "d2d7d8a808b5efeb09fe529034a30bd772902d84";
          };
          buildPhase = ''
            ${pkgs.nodePackages.node-gyp}/bin/node-gyp rebuild --nodedir=${lib.getDev nodejs} # /include/node
          '';
         nativeBuildInputs = [ pkgs.python3 ];
          nodeBuildInputs = [
            (s."bufio@~1.0.7")
            (s."loady@~0.0.5")
          ];
        };

        # https://github.com/Profpatsch/yarn2nix/issues/56
        "char-regex@1.0.2" = {
          inherit (super."char-regex@1.0.2") key;
          drv = super."char-regex@1.0.2".drv.overrideAttrs (_: {
            dontMakeSourcesWritable = true;
            postUnpack = ''
              chmod +x $sourceRoot
              chmod -R +rw $sourceRoot
            '';
          });
        };

        "usb@1.8.8" = {
          inherit (super."usb@1.8.8") key;
          drv = super."usb@1.8.8".drv.overrideAttrs (attrs: {
            nativeBuildInputs = [ pkgs.python3 pkgs.systemd pkgs.v8_5_x nodejs pkgs.libusb1 ];
            dontBuild = false;
            buildPhase = ''
              ln -s ${nixLib.linkNodeDeps { name=attrs.name; dependencies=attrs.passthru.nodeBuildInputs; }} node_modules
              ${pkgs.nodePackages.node-gyp}/bin/node-gyp rebuild --nodedir=${lib.getDev nodejs} # /include/node
            '';
          });
        };

        "node-hid@1.3.0" = {
          inherit (super."node-hid@1.3.0") key;
          drv = super."node-hid@1.3.0".drv.overrideAttrs (attrs: {
            nativeBuildInputs = [ pkgs.python3 pkgs.systemd pkgs.v8_5_x nodejs pkgs.libusb1 pkgs.pkg-config ];
            dontBuild = false;
            buildPhase = ''
              ln -s ${nixLib.linkNodeDeps { name=attrs.name; dependencies=attrs.passthru.nodeBuildInputs; }} node_modules
              ${pkgs.nodePackages.node-gyp}/bin/node-gyp rebuild --nodedir=${lib.getDev nodejs} # /include/node
            '';
          });
        };

        "hw-app-avalanche@0.1.0" = super._buildNodePackage rec {
          key = "hw-app-avalanche";
          version = "0.1.0";
          src = getThunkSrc ./deps/hw-app-avalanche;
          buildPhase = ''
            ln -s $nodeModules node_modules
            node $nodeModules/.bin/tsc
            node $nodeModules/.bin/tsc -m ES6 --outDir lib-es
          '';
          nodeModules = nixLib.linkNodeDeps {
            name = "hw-app-avalanche";
            dependencies = nodeBuildInputs ++ [
              (s."@types/node@^16.10.3")
              (s."@types/jest@^26.0.24")
              (s."typescript@^4.4.3")
            ];
          };
          passthru = { inherit nodeModules; };
          NODE_PATH = nodeModules;
          nodeBuildInputs = [
            (s."@ledgerhq/hw-transport@^6.3.0")
            (s."bip32-path@^0.4.2")
            (s."create-hash@1.2.0")
            (s."jest@^26.4.1")
          ];
        };

      };

  deps = nixLib.buildNodeDeps
    (lib.composeExtensions
      (pkgs.callPackage npmDepsNix {
        fetchgit = builtins.fetchGit;
      })
      localOverrides);

  src0 = lib.sources.cleanSourceWith {
    src = ./.;
    filter = p: _: let
      p' = baseNameOf p;
      srcStr = builtins.toString ./.;
    in p' != "node_modules";
  };

  src = lib.sources.sourceFilesBySuffices src0 [
    ".js" ".cjs" ".ts" ".json"
  ];
in rec {
  inherit deps npmDepsNix npmPackageNix getThunkSrc;

  testModules = nixLib.buildNodePackage ({
    src = pkgs.runCommand "package-json" {} ''
      mkdir $out
      cp ${./package.json} $out/package.json
    '';
  } // nixLib.callTemplate npmPackageNix deps);

  testScript = pkgs.writeShellScriptBin "mocha-wrapper" ''
    suite="$(readlink -e ''${1:-${testPackage}})"
    shift

    LEDGER_APP="$(readlink -e ''${LEDGER_APP})"

    cd "$suite"

    export NODE_PATH=${testModules}/node_modules
    rm ./node_modules
    ln -s $NODE_PATH ./node_modules

    export NO_UPDATE_NOTIFIER=true
    exec ${pkgs.yarn}/bin/yarn run test ./*-tests.ts
  '';

  testPackage = nixLib.buildNodePackage ({
    inherit src;
  } // nixLib.callTemplate npmPackageNix deps);
}
