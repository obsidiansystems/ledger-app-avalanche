# Avalanche Hardware Wallet for Ledger

## WIP 0.6.1

* Support "Create Chain" and "Creat Subnet transactions.
* Improve batching support, making the transaction parsing more robust in the process.
* Bump SDK to 2.1.
* Revamp test suite to use non-deprecated method of interacting with speculos.

## 0.6.0

* More P <-> X interopt is supported.
* Prompts are now batched for easier usage.
* Testsuite now is in type script using ES6 modules.

## 0.5.7 -- 0.5.9

Just small bugfixes

## 0.5.5 -- 0.5.6

Improvements relating to Ethereum / C chain.

## 0.5.4

* Improve wei to AVAX or NAVAX rendering.

## 0.5.3

* Fix Ethereum / C chain issue.

## 0.5.2

Just build infrastructure improvements, no app proper changes.

## 0.5.1

* Fix Ethereum / C chain issue making RLP parsing more robust.

## 0.5.0

* Vastly improve Ethereum support for the C Chain.

## 0.4.0

* Support C chain import and export.
* Support C chain transfer of Avalanche Native Assets (ANTs).
* Support C chain deposit of ANTs to a token contract.
* Support signing of a hash with Ethereum BIP32 paths.
* Other miscellaneous bug fixes.

## 0.3.1

* Support P chain import and export.
* Support P chain validator and delegator transactions.
* Restrict BIP32 paths to those allowed by AVAX.
* Add setting to reject or accept sign hash operations.
* Display amounts in AVAX instead of nAVAX.
* Update blockchain ids and handle different networks better.
* Other miscellaneous bug fixes.

## 0.2.0

* Move to Everest network.
* Switch "get public key" APDU to "get public key hash" instead.
* Allow custom HRP in "get public key hash" and "get extended public key" APDUs to be used in Ledger prompt.
* Switch "sign hash" APDU to a new multi-signature protocol.
* Update icons and name.
* Enable WebUSB and fix U2F.
* Fix bugs.

## 0.1.0

* Initial version for Denali test network.
