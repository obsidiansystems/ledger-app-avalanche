import {
  makeAva,
  transportOpen,
  checkSignHash0,
  setAutomationRules,
  defaultRejectAutomationRules,
  deleteEvents,
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
  context('Generative tests', function (this: Mocha.Suite) {
    it('can sign a hash-sized sequence of bytes', async function (this: Mocha.Context) {
      // Need 'function' to get 'this' for mocha.
      return await fc.assert(fc.asyncProperty(fc.array(subAddressGen,1,10), fc.hexaString(64, 64), async (subAccts: string[], hashHex: string) => {
        this.flushStderr();
        await checkSignHash0(this, account, subAccts, hashHex);
      }));
    });

    it('does not produce signatures when prompt is rejected', async function () { // Need 'function' to get 'this' for mocha.
      return await fc.assert(fc.asyncProperty(fc.array(subAddressGen), fc.hexaString(64, 64), async (subAccts, hashHex) => {
        this.flushStderr();
        if (subAccts.length == 0) return;
        await setAutomationRules(defaultRejectAutomationRules);
        await deleteEvents();
        let ava = await makeAva();

        try {
          await ava.signHash(account, subAccts, Buffer.from(hashHex, "hex"));
          throw "Rejected prompts should reject";
        } catch(e) {
          expect(e).has.property('statusCode', 0x6985);
          expect(e).has.property('statusText', 'CONDITIONS_OF_USE_NOT_SATISFIED');
        }
      }));
    });

    it('rejects incorrectly-sized hashes', async function () { // Need 'function' to get 'this' for mocha.
      return await fc.assert(fc.asyncProperty(fc.array(subAddressGen), fc.hexaString(), async (subAccts, hashHex) => {
        const transport = await transportOpen();
        const ava = await makeAva();

        this.flushStderr();
        const hash = Buffer.from(hashHex, "hex");
        const firstMessage = Buffer.concat([
          ava.uInt8Buffer(subAccts.length),
          hash,
          ava.encodeBip32Path(account)
        ]);
        try {
          await transport.send(ava.CLA, ava.INS_SIGN_HASH, 0x00, 0x00, firstMessage);
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
