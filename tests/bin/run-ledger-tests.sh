#!/usr/bin/env bash

export LEDGER_APP="${LEDGER_APP:-$(readlink -f bin/app.elf)}"
echo $LEDGER_APP

MY_DIR="$(dirname $(readlink -f "${BASH_SOURCE[0]}"))/.."
MY_NODE_MODULES=$MY_DIR/node_modules
suite="${1:-$MY_DIR}"
shift

if [[ ! ($suite == /nix/*) && -f $suite/hw-app-avalanche/src/Avalanche.js ]]; then
  pushd $suite
  nix-shell -A 'passthru.deps."hw-app-avalanche@0.1.0"' --run "pushd hw-app-avalanche; node \$nodeModules/.bin/babel --source-maps -d lib src; popd"
  popd
else
  rm $suite/node_modules
  ln -s $MY_NODE_MODULES $suite/node_modules
fi

$MY_NODE_MODULES/.bin/mocha $suite \
  --exit \
  --require $suite/hooks.js \
  --config $suite/.mocharc.cjs "$@"
