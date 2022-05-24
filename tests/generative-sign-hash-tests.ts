import {
  PromptsPromise,
  flowAccept,
  signHashPrompts,
} from "./common";

import chai from 'chai';
import chai_bytes from 'chai-bytes';
export const { expect } = chai.use(chai_bytes);
chai.config.showDiff = true;
chai.config.truncateThreshold = 0;
import secp256k1 from 'bcrypto/lib/secp256k1';
import fc from 'fast-check';
import bip from 'bip32-path';

const prefix = bip.fromString("m/44'/9000'").toPathArray();
const bipNotHardened = fc.integer(0x7fffffff);
const bipHardened = bipNotHardened.map(a => a + 0x80000000);
const account = bip.fromPathArray(prefix.concat([0 + 0x80000000]));
const subAddressGen = fc.tuple(fc.integer(0,1), fc.integer(0,2147483648)).map(([a, b]) => bip.fromPathArray([a,b]));

describe("Sign Hash tests", () => {
  context('Generative tests', function () {
    it('can sign a hash-sized sequence of bytes', async function () { // Need 'function' to get 'this' for mocha.
      return await fc.assert(fc.asyncProperty(fc.array(subAddressGen,1,10), fc.hexaString(64, 64), async (subAccts, hashHex) => {
        let ui: PromptsPromise<{ promptsMatch: true }> = {
          promptsPromise: (async () => ({ promptsMatch: true }))(),
          cancel: () => {}
        };
        try {
          this.flushStderr();

          const expectedPrompts = signHashPrompts(hashHex.toUpperCase(), account.toString(true));
          ui = await flowAccept(this.speculos, expectedPrompts) as PromptsPromise<{ promptsMatch: true }>;
          const hash = Buffer.from(hashHex, "hex");
          const sigs = this.ava.signHash(account, subAccts, hash);

          const sv = await sigs;

          await (await ui.promptsPromise).promptsMatch;
          for (const ks of sv) {
            const [keySuffix, sig] = ks;

            const key = await this.ava.getWalletExtendedPublicKey(account.toString() + "/" + keySuffix);

            const recovered = secp256k1.recover(Buffer.from(hashHex, "hex"), sig.slice(0, 64), sig[64], false);
            expect(recovered).is.equalBytes(key.public_key);
          }
        } catch(e) {
          ui.cancel();
          throw(e);
        }
      }));
    });

    it('does not produce signatures when prompt is rejected', async function () { // Need 'function' to get 'this' for mocha.
      return await fc.assert(fc.asyncProperty(fc.array(subAddressGen), fc.hexaString(64, 64), async (subAccts, hashHex) => {
        let ui = { cancel: () => {} };
        try {
          this.flushStderr();
          if (subAccts.length == 0) return;

          const expectedPrompts = signHashPrompts(hashHex.toUpperCase(), account.toString(true));
          const ui = await flowAccept(this.speculos, expectedPrompts, "Reject");
          const hash = Buffer.from(hashHex, "hex");
          try {
            await this.ava.signHash(account, subAccts, hash);
            throw "Rejected prompts should reject";
          } catch(e) {
            expect(e).has.property('statusCode', 0x6985);
            expect(e).has.property('statusText', 'CONDITIONS_OF_USE_NOT_SATISFIED');
          }

          await (await ui.promptsPromise).promptsMatch;
        } catch(e) {
          ui.cancel();
          throw(e);
        }
      }));
    });

    it('rejects incorrectly-sized hashes', async function () { // Need 'function' to get 'this' for mocha.
      return await fc.assert(fc.asyncProperty(fc.array(subAddressGen), fc.hexaString(), async (subAccts, hashHex) => {
        this.flushStderr();
        const hash = Buffer.from(hashHex, "hex");
        const firstMessage = Buffer.concat([
          this.ava.uInt8Buffer(subAccts.length),
          hash,
          this.ava.encodeBip32Path(account)
        ]);
        try {
          await this.speculos.send(this.ava.CLA, this.ava.INS_SIGN_HASH, 0x00, 0x00, firstMessage);
          throw "Expected rejection";
        } catch (e) {
          expect(e).has.property('statusCode', subAccts.length > 0
            ? 0x6C00 // WRONG_LENGTH
            : 0x6B00 // WRONG_PARAM
          );
        }
      }));
    });
  });
});
