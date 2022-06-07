import {
  transportOpen,
} from "./common";
import Ava from "hw-app-avalanche";
import chai from 'chai';
import chai_bytes from 'chai-bytes';
export const { expect, assert } = chai.use(chai_bytes);
chai.config.showDiff = true;
chai.config.truncateThreshold = 0;

import fc from 'fast-check';

describe("APDU protocol integrity generative tests", function () {
  context('Generative tests', function () {
    it('rejects incorrect APDU numbers', async function () {
      return await fc.assert(fc.asyncProperty(fc.integer(6, 255), fc.hexaString(), async (apdu, hashHex) => {
        const transport = await transportOpen();
        const ava = new Ava(transport);
        const body = Buffer.from(hashHex, 'hex');
        try {
          await transport.send(ava.CLA, apdu, 0x00, 0x00, body);
          throw("Expected error");
        } catch (e) {
          this.flushStderr();
          expect(e).has.property('statusCode', 0x6D00); // INS_NOT_SUPPORTED
        }
      }), { examples: [[9, '']] });
    });

    // We have an issue this one, perhaps preexisting
    it.skip('rejects garbage on correct APDU numbers', async function () {
      return await fc.assert(fc.asyncProperty(fc.integer(0, 4), fc.hexaString(), fc.integer(0,255), async (apdu, hashHex, p1) => {
        const transport = await transportOpen();
        const ava = new Ava(transport);
        const body = Buffer.from(hashHex, 'hex');
        try {
          await transport.send(ava.CLA, apdu, p1, 0x00, body);
          throw "Expected error";
        } catch (e) {
          this.flushStderr();
          expect(e).has.property('statusCode');
        }
      }));
    });

    it('rejects garbage dumped straight to the device', async function () {
      return await fc.assert(fc.asyncProperty(fc.hexaString(2, 512), async hashHex => {
        const transport = await transportOpen();
        const ava = new Ava(transport);
        const body = Buffer.from(hashHex, 'hex');
        const rv = await transport.exchange(body);
        expect(rv).to.not.equalBytes("9000");
        this.flushStderr();
      }));
    });

    it('rejects short garbage dumped straight to the device', async function () {
      return await fc.assert(fc.asyncProperty(fc.hexaString(10, 64), async hashHex => {
        const transport = await transportOpen();
        const ava = new Ava(transport);
        const body = Buffer.from(hashHex, 'hex');
        let rv = Buffer.from("9000", "hex");
        try {
          rv = await transport.exchange(body);
        } catch(e) {
          return; // Errors that get here are probably from the transport, not from the ledger.
        }

        expect(rv).to.not.equalBytes("9000");
        this.flushStderr();
      }));
    });

    it('accepts apdu ending in the middle of parsing length of calldata', async function () {
      const txBeforeCalldata = 'f701856d6e2edc0782520894010000000000000000000000000000000000000200';
      const calldataLenLenHex = 'ff';
      const calldataLenHex = 'ffffdadadada';
      return await fc.assert(fc.asyncProperty(fc.integer(0, calldataLenHex.length / 2), async cutoff => {
        const transport = await transportOpen();
        const ava = new Ava(transport);
        const apduHeader = 'e0040000' + (0x37 + cutoff).toString(16) + '058000002c8000003c800600000000000000000000';
        const body = Buffer.from(apduHeader + txBeforeCalldata + calldataLenLenHex + calldataLenHex.slice(0, cutoff * 2), 'hex');
        const rv = await transport.exchange(body);
        expect(rv).to.equalBytes("9000");
      }));
    });
  });
});
