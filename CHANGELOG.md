# Avalanche Hardware Wallet for Ledger

## 0.4.0

* Support C chain import and export.
* Support C chain transfer of Avalanche Native Assets (ANTs).
* Support C chain deposit of ANTs to a token contract.
* Support signing of a hash with Ethereum BIP32 paths.
* Bump AvalancheJS to 0.3.2 Apricot release.
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
