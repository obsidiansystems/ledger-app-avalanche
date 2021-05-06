describe("Basic Tests", () => {
  context('Basic APDUs', function () {
    it('can fetch the version of the app', async function () {
      const cfg = await this.ava.getAppConfiguration();
      expect(cfg).to.be.a('object');
      expect(cfg).to.have.property("version", "0.5.3");
      expect(cfg).to.have.property("name", "Avalanche");
    });
    it('returns the expected wallet ID', async function () {
      const id = await this.ava.getWalletId();
      expect(id).to.equalBytes('f0e476edaffc');
    });
  });

  context('Public Keys', function () {
    it('can retrieve an address from the app', async function() {
      const flow = await flowAccept(this.speculos);
      const key = await this.ava.getWalletAddress("44'/9000'/0'/0/0");
      expect(key).to.equalBytes('41c9cc6fd27e26e70f951869fb09da685a696f0a');
      await flow.promptsPromise;
    });
    it('can retrieve a different address from the app', async function() {
      await flowAccept(this.speculos);
      const key = await this.ava.getWalletAddress("44'/9000'/0'/0/1");
      expect(key).to.equalBytes('68c2185ed05ab18220808fb6a11731c9952bd9aa');
    });
    it('can retrieve a change address from the app', async function() {
      await flowAccept(this.speculos);
      const key = await this.ava.getWalletAddress("44'/9000'/0'/1/0");
      expect(key).to.equalBytes('95250c0b1dccfe79388290381e44cdf6956b55e6');
    });
    it('cannot retrieve a non-hardened account from the app', async function() {
      try {
        await this.ava.getWalletAddress("44'/9000'/0/0/0");
        throw "Expected failure";
      } catch (e) {
        expect(e).has.property('statusCode', 0x6982);
        expect(e).has.property('statusText', 'SECURITY_STATUS_NOT_SATISFIED');
      }
    });
    it('produces the expected top-level extended key for the zeroeth account', async function() {
      await flowAccept(this.speculos);
      const key = await this.ava.getWalletExtendedPublicKey("44'/9000'/0'");
      expect(key).to.have.property('public_key').equalBytes('043033e21973c30ed7e50fa546f8690e25685ac900c3be24c5f641b9c1b959344151169853808be753760dd6aeddd3556f0efaafa6279b64f0ae49de0417ea70b2');
      expect(key).to.have.property('chain_code').to.equalBytes('590c70e192c597c23ad7c8185c12952b50525ff9d839a95bf6a7e6da359ce873');
    });
    it('can retrieve an extended public key from the app', async function() {
      await flowAccept(this.speculos);
      const key = await this.ava.getWalletExtendedPublicKey("44'/9000'/0'/0/0");
      expect(key).to.have.property('public_key').to.equalBytes('046b3cdd6f3313c11165a28463715f9cdb704f8163d04f25e814c0471c58da35637469a60d22c1eab5347c3a0a2920f27539730ebfc74d172c200a8164eaa70878');
      expect(key).to.have.property('chain_code').to.equalBytes('3b63e0f576c7b865a46c357bcfb2751e914af951f84e5eef0592e9ea7e3ea3c2');
    });
  });

  context('Signing', function () {
    it('can sign a hash-sized sequence of bytes with one path', async function () {
      await checkSignHash(
        this,
        "44'/9000'/0'",
        ["0/0"],
        "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
      );
    });

    it('can sign a hash-sized sequence of bytes with many paths', async function () {
      await checkSignHash(
        this,
        "44'/9000'/0'",
        ["0/0", "1/20", "1'/200'", "3000'/90030'"],
        "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
      );
    });

    it('cannot sign a hash-sized sequence of bytes with long paths', async function () {
      try {
        await checkSignHash(
          this,
          "44'/9000'/0'",
          ["0/0/0/0/0"],
          "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
        );
        throw "Expected failure";
      } catch (e) {
        expect(e).has.property('statusCode', 0x9200); // MEMORY_ERROR
        expect(e).has.property('statusText', 'UNKNOWN_ERROR');
      }
    });

    it('refuses to sign when given an invalid path suffix', async function () {
      const pathPrefix = "44'/9000'/0'";
      const firstMessage = Buffer.concat([
        this.ava.uInt8Buffer(1),
        Buffer.from("111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000", "hex"),
        this.ava.encodeBip32Path(BIPPath.fromString(pathPrefix)),
      ]);

      const prompts = await flowAccept(
        this.speculos,
        signHashPrompts(
          "111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000",
          pathPrefix,
        ),
      );
      await this.speculos.send(this.ava.CLA, this.ava.INS_SIGN_HASH, 0x00, 0x00, firstMessage);
      await prompts.promptsMatch;

      try {
        await this.speculos.send(this.ava.CLA, this.ava.INS_SIGN_HASH, 0x81, 0x00, Buffer.from("00001111", 'hex'));
        throw "Expected failure";
      } catch (e) {
        expect(e).has.property('statusCode', 0x6a80); // WRONG_VALUES
        expect(e).has.property('statusText', 'INCORRECT_DATA');
      }
    });

    it('rejects signing hash when disallowed in settings', async function () {
      let flipHashPolicy = async (target) => {return await automationStart(this.speculos, async (speculos, screens) => {
        speculos.button("Rr");
        while((await screens.next()).body != "Configuration") speculos.button("Rr");
        speculos.button("RLrl");
        let policy;
        while((policy = await screens.next()).header != "Sign hash policy") {
          speculos.button("Rr");
        }
        while(policy.body != target) {
          speculos.button("RLrl");
          policy = await screens.next();
        }
        do { speculos.button("Rr") } while((await screens.next()).body != "Main menu");
        speculos.button("RLrl");

        return { promptsMatch: true };

      })};
      await (await flipHashPolicy("Disallow")).promptsPromise;

      try {
        // we could have a signHashExpectFailure, but it's just this line anyways.
        await this.ava.signHash(
          BIPPath.fromString("44'/9000'/1'"),
          [BIPPath.fromString("0/0", false)],
          Buffer.from("111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000", "hex"));
        throw "Expected failure";
      } catch (e) {
        expect(e).has.property('statusCode', 0x6985); // REJECT
        expect(e).has.property('statusText', 'CONDITIONS_OF_USE_NOT_SATISFIED');
      } finally {
        await (await flipHashPolicy("Allow w/ warning")).promptsPromise;
      }
    });

    it('can sign a transaction based on the serialization reference in verbose mode', async function () {
      const pathPrefix = "44'/9000'/0'";
      const pathSuffixes = ["0/0", "0/1", "1/100"];
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Transaction"}],
        [{header:"Transfer",body:"0.000012345 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
        [{header:"Fee",body:"0.123444444 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = signTransaction(this.ava, pathPrefix, pathSuffixes);
      await ui.promptsPromise;
      await checkSignTransactionResult(this.ava, await sigPromise, pathPrefix, pathSuffixes);
    });

    it('can display a transaction with lots of digits', async function () {
      const pathPrefix = "44'/9000'/0'";
      const pathSuffixes = ["0/0", "0/1", "1/100"];
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Transaction"}],
        [{header:"Transfer",body:"0.123456789 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
        [{header:"Fee",body:"0.876543211 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = signTransaction(this.ava, pathPrefix, pathSuffixes, {
        "outputAmount": Buffer.from([0x00, 0x00, 0x00, 0x00, 0x07, 0x5b, 0xcd, 0x15]),
        "inputAmount": Buffer.from([0x00, 0x00, 0x00, 0x00, 0x3b, 0x9a, 0xca, 0x00]),
      });
      await ui.promptsPromise;
      await checkSignTransactionResult(this.ava, await sigPromise, pathPrefix, pathSuffixes);
    });

    it('can display a transaction with no decimal', async function () {
      const pathPrefix = "44'/9000'/0'";
      const pathSuffixes = ["0/0", "0/1", "1/100"];
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Transaction"}],
        [{header:"Transfer",body:"1 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
        [{header:"Fee",body:"1 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = signTransaction(this.ava, pathPrefix, pathSuffixes, {
        "outputAmount": Buffer.from([0x00, 0x00, 0x00, 0x00, 0x3b, 0x9a, 0xca, 0x00]),
        "inputAmount": Buffer.from([0x00, 0x00, 0x00, 0x00, 0x77, 0x35, 0x94, 0x00]),
      });
      await ui.promptsPromise;
      await checkSignTransactionResult(this.ava, await sigPromise, pathPrefix, pathSuffixes);
    });

    it('can sign a sample fuji transaction', async function () {
      const txn = Buffer.from([
        // Codec ID
        0x00, 0x00,
        // Type ID
        0x00, 0x00, 0x00, 0x00,
        // Network ID (fuji)
        0x00, 0x00, 0x00, 0x05,
        // Blockchain ID (fuji)
        0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c,
        0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
        0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6,
        0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,
        // number of outputs
        0x00, 0x00, 0x00, 0x02,
        // transferrable output 1
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x07, // output type (SECP256K1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // locktime
        0x00, 0x00, 0x00, 0x01, // threshold
        0x00, 0x00, 0x00, 0x01, // number of addresses
        0x7F, 0x67, 0x1C, 0x73, 0x0D, 0x48, 0x07, 0xC2,
        0x9E, 0xA1, 0x9B, 0x19, 0xA2, 0x3C, 0x70, 0x0B,
        0x19, 0x8F, 0x8B, 0x51, // 20-byte address
        // transferrable ouput 2
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x07, // output type (SECP256K1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x6A, 0xCB, 0xD8, // amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // locktime
        0x00, 0x00, 0x00, 0x01, // threshold
        0x00, 0x00, 0x00, 0x01, // number of addresses
        0xA4, 0xAF, 0xAB, 0xFF, 0x30, 0x81, 0x95, 0x25,
        0x99, 0x90, 0xA9, 0xE5, 0x31, 0xBD, 0x82, 0x30,
        0xD1, 0x1A, 0x9A, 0x2A, // 20-byte address
        // number of inputs
        0x00, 0x00, 0x00, 0x02,
        // transferrable input 1
        0x1C, 0x03, 0x06, 0xE5, 0x8B, 0x75, 0x4E, 0xEB,
        0x92, 0xE7, 0xA5, 0x79, 0xC5, 0x9A, 0x69, 0x33,
        0x23, 0xCD, 0x99, 0x94, 0xA5, 0x94, 0x61, 0x62,
        0x72, 0x6F, 0x3B, 0x68, 0x0E, 0x9E, 0x48, 0x34, // 32-byte TX ID
        0x00, 0x00, 0x00, 0x00, // UTXO index
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x05, // type ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // amount
        0x00, 0x00, 0x00, 0x01, // number of address indices
        0x00, 0x00, 0x00, 0x00, // address index 1
        // transferrable input 2
        0x29, 0x71, 0x0D, 0xE0, 0x93, 0xE2, 0xF4, 0x10,
        0xB5, 0xA3, 0x5E, 0x2C, 0x60, 0x59, 0x38, 0x39,
        0x2D, 0xA0, 0xDE, 0x80, 0x2C, 0x74, 0xE2, 0x5D,
        0x78, 0xD2, 0xBF, 0x11, 0x87, 0xDC, 0x9A, 0xD6, // 32-byte TX ID
        0x00, 0x00, 0x00, 0x00, // UTXO index
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x05, // type ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x11, 0x9C, // amount
        0x00, 0x00, 0x00, 0x01, // number of address indices
        0x00, 0x00, 0x00, 0x00, // address index 1
        // memo length
        0x00, 0x00, 0x00, 0x04,
        // memo
        0x00, 0x00, 0x00, 0x00,
      ]);

      const pathPrefix = "44'/9000'/0'";
      const pathSuffixes = ["0/0", "0/1", "1/100"];
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Transaction"}],
        [{header:"Transfer",body:"0.000001 AVAX to fuji10an3cucdfqru984pnvv6y0rspvvclz634xwwhs"}],
        [{header:"Transfer",body:"0.006999 AVAX to fuji15jh6hlessx2jtxvs48jnr0vzxrg34x32vuc7jc"}],
        [{header:"Fee",body:"0.001 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = this.ava.signTransaction(
        BIPPath.fromString(pathPrefix),
        pathSuffixes.map(x => BIPPath.fromString(x, false)),
        txn,
      );
      await ui.promptsPromise;
      await checkSignTransactionResult(this.ava, await sigPromise, pathPrefix, pathSuffixes);
    });

    it('can skip a change address in sample fuji transaction', async function () {
      const txn = Buffer.from([
        // Codec ID
        0x00, 0x00,
        // Type ID
        0x00, 0x00, 0x00, 0x00,
        // Network ID (fuji)
        0x00, 0x00, 0x00, 0x05,
        // Blockchain ID (fuji)
        0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c,
        0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
        0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6,
        0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,
        // number of outputs
        0x00, 0x00, 0x00, 0x02,
        // transferrable output 1
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x07, // output type (SECP256K1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // locktime
        0x00, 0x00, 0x00, 0x01, // threshold
        0x00, 0x00, 0x00, 0x01, // number of addresses
        0x7F, 0x67, 0x1C, 0x73, 0x0D, 0x48, 0x07, 0xC2,
        0x9E, 0xA1, 0x9B, 0x19, 0xA2, 0x3C, 0x70, 0x0B,
        0x19, 0x8F, 0x8B, 0x51, // 20-byte address
        // transferrable ouput 2
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x07, // output type (SECP256K1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x6A, 0xCB, 0xD8, // amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // locktime
        0x00, 0x00, 0x00, 0x01, // threshold
        0x00, 0x00, 0x00, 0x01, // number of addresses
        0xF1, 0x4C, 0x91, 0xBE, 0x3A, 0x26, 0xE3, 0xCE,
        0x30, 0xF9, 0x70, 0xD8, 0x72, 0x57, 0xFD, 0x2F,
        0xB3, 0xDF, 0xBB, 0x7F, // 20-byte address
        // number of inputs
        0x00, 0x00, 0x00, 0x02,
        // transferrable input 1
        0x1C, 0x03, 0x06, 0xE5, 0x8B, 0x75, 0x4E, 0xEB,
        0x92, 0xE7, 0xA5, 0x79, 0xC5, 0x9A, 0x69, 0x33,
        0x23, 0xCD, 0x99, 0x94, 0xA5, 0x94, 0x61, 0x62,
        0x72, 0x6F, 0x3B, 0x68, 0x0E, 0x9E, 0x48, 0x34, // 32-byte TX ID
        0x00, 0x00, 0x00, 0x00, // UTXO index
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x05, // type ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // amount
        0x00, 0x00, 0x00, 0x01, // number of address indices
        0x00, 0x00, 0x00, 0x00, // address index 1
        // transferrable input 2
        0x29, 0x71, 0x0D, 0xE0, 0x93, 0xE2, 0xF4, 0x10,
        0xB5, 0xA3, 0x5E, 0x2C, 0x60, 0x59, 0x38, 0x39,
        0x2D, 0xA0, 0xDE, 0x80, 0x2C, 0x74, 0xE2, 0x5D,
        0x78, 0xD2, 0xBF, 0x11, 0x87, 0xDC, 0x9A, 0xD6, // 32-byte TX ID
        0x00, 0x00, 0x00, 0x00, // UTXO index
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
        0x00, 0x00, 0x00, 0x05, // type ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x11, 0x9C, // amount
        0x00, 0x00, 0x00, 0x01, // number of address indices
        0x00, 0x00, 0x00, 0x00, // address index 1
        // memo length
        0x00, 0x00, 0x00, 0x04,
        // memo
        0x00, 0x00, 0x00, 0x00,
      ]);

      const pathPrefix = "44'/9000'/0'";
      const pathSuffixes = ["0/0", "0/1", "1/100"];
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Transaction"}],
        [{header:"Transfer",body:"0.000001 AVAX to fuji10an3cucdfqru984pnvv6y0rspvvclz634xwwhs"}],
        [{header:"Transfer",body:"0.006999 AVAX to fuji179xfr036ym3uuv8ewrv8y4la97ealwmlfg8yrr"}],
        [{header:"Fee",body:"0.001 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = this.ava.signTransaction(
        BIPPath.fromString(pathPrefix),
        pathSuffixes.map(x => BIPPath.fromString(x, false)),
        txn,
        BIPPath.fromString("44'/9000'/0'/0/0"),
      );
      await ui.promptsPromise;
      await checkSignTransactionResult(this.ava, await sigPromise, pathPrefix, pathSuffixes);
    });

    it('rejects a transaction that has extra data', async function () {
      try {
        const ui = await flowMultiPrompt(this.speculos, [
          [{header:"Sign",body:"Transaction"}],
          [{header:"Transfer",body:"0.000012345 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
          [{header:"Fee",body:"0.123444444 AVAX"}],
        ], "Next", "Next");
        await signTransaction(this.ava, "44'/9000'/0'", ["0/0"], {
          extraEndBytes: Buffer.from([0x00])
        });
        await ui.promptsPromise;
        throw "Signing should have been rejected";
      } catch (e) {
        expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
        expect(e).has.property('statusText', 'UNKNOWN_ERROR');
      }
    });

    it('rejects an unrecognized codec ID', async function () {
      await expectSignFailure(this.speculos, this.ava, { codecId: Buffer.from([0x01, 0x00]) });
    });

    it('rejects an unrecognized type ID', async function () {
      await expectSignFailure(this.speculos, this.ava, { typeId: Buffer.from([0x01, 0x00, 0x00, 0x00]) });
    });

    it('rejects an unrecognized network ID', async function () {
      await expectSignFailure(
        this.speculos,
        this.ava,
        { networkId: Buffer.from([0x01, 0x00, 0x00, 0x00]) },
        [],
      );
    });

    it('rejects a recognized network ID that does not match blockchain ID', async function () {
      await expectSignFailure(
        this.speculos,
        this.ava,
        { networkId: Buffer.from([0x00, 0x00, 0x00, 0x01]) },
        [],
      );
    });

    it('rejects an unrecognized output type ID', async function () {
      await expectSignFailure(
        this.speculos,
        this.ava,
        { outputTypeId: Buffer.from([0x01, 0x00, 0x00, 0x00]) },
        [[{header:"Sign",body:"Transaction"}]],
      );
    });

    it('rejects a different unrecognized output type ID', async function () {
      await expectSignFailure(
        this.speculos,
        this.ava,
        { outputTypeId: Buffer.from([0x00, 0x00, 0xf0, 0x00]) },
        [[{header:"Sign",body:"Transaction"}]],
      );
    });

    it('rejects an unrecognized input type ID', async function () {
      await expectSignFailure(
        this.speculos,
        this.ava,
        { inputTypeId: Buffer.from([0x01, 0x00, 0x00, 0x00]) },
        [
          [{header:"Sign",body:"Transaction"}],
          [{header:"Transfer",body:"0.000012345 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
        ],
      );
    });

    it('rejects unsupported asset IDs', async function () {
      const assetId = Buffer.from([
        0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
        0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
        0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
        0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xab, // fuji AVAX assetID, except last byte is wrong
      ]);

      await expectSignFailure(
        this.speculos,
        this.ava,
        {
          inputAssetId: assetId,
          outputAssetId: assetId
        },
        [
          [{header:"Sign",body:"Transaction"}],
        ],
      );
    });

   it('rejects an AVAX asset ID from a different network', async function () {
     const assetId = Buffer.from([
       0x21, 0xe6, 0x73, 0x17, 0xcb, 0xc4, 0xbe, 0x2a,
       0xeb, 0x00, 0x67, 0x7a, 0xd6, 0x46, 0x27, 0x78,
       0xa8, 0xf5, 0x22, 0x74, 0xb9, 0xd6, 0x05, 0xdf,
       0x25, 0x91, 0xb2, 0x30, 0x27, 0xa8, 0x7d, 0xff, // mainnet AVAX asset ID
     ]);

     await expectSignFailure(
       this.speculos,
       this.ava,
       {
         inputAssetId: assetId,
         outputAssetId: assetId
       },
       [
         [{header:"Sign",body:"Transaction"}],
       ],
     );
   });

   it('rejects multi-address outputs', async function () {
     const output = Buffer.from([
       0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
       0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
       0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
       0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
       0x00, 0x00, 0x00, 0x02, // number of addresses
       0xA4, 0xAF, 0xAB, 0xFF, 0x30, 0x81, 0x95, 0x25,
       0x99, 0x90, 0xA9, 0xE5, 0x31, 0xBD, 0x82, 0x30,
       0xD1, 0x1A, 0x9A, 0x2A, // 20-byte address 1
       0xA5, 0xAF, 0xAB, 0xFF, 0x30, 0x81, 0x95, 0x25,
       0x99, 0x90, 0xA9, 0xE5, 0x31, 0xBD, 0x82, 0x30,
       0xD1, 0x1A, 0x9A, 0x2A, // 20-byte address 2
     ]);
     await expectSignFailure(
       this.speculos,
       this.ava,
       { transferrableOutput: output },
       [
         [{header:"Sign",body:"Transaction"}],
       ],
     );
    });
  });

  describe("X-chain Import and Export", function() {
    const pathPrefix = "44'/9000'/0'";
    const pathSuffixes = ["0/0", "0/1", "100/100"];
    const fujiAssetId = [
      0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
      0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
      0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
      0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa,
    ];
    const fujiPChainID = [
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const fujiCChainID = [
      0x7f, 0xc9, 0x3d, 0x85, 0xc6, 0xd6, 0x2c, 0x5b,
      0x2a, 0xc0, 0xb5, 0x19, 0xc8, 0x70, 0x10, 0xea,
      0x52, 0x94, 0x01, 0x2d, 0x1e, 0x40, 0x70, 0x30,
      0xd6, 0xac, 0xd0, 0x02, 0x1c, 0xac, 0x10, 0xd5,
    ];
    const importTxn = sourceChainID => Buffer.from([
      0x00, 0x00,
      // base tx:
      0x00, 0x00, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x05,
      // blockchainID: (fuji)
      0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c,
      0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
      0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6,
      0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,
      0x00, 0x00, 0x00, 0x01,
      ... fujiAssetId,
      0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01,
      0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e,
      0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46, 0x1c, 0x89,
      0x43, 0xab, 0x08, 0x59, 0x00, 0x00, 0x00, 0x01,
      0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81,
      0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01,
      0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
      0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
      0x00, 0x00, 0x00, 0x05,
      ... fujiAssetId,
      0x00, 0x00, 0x00, 0x05,
      0x00, 0x00, 0x00, 0x00, 0x07, 0x5b, 0xcd, 0x15,
      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07,
      0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
      0x00, 0x01, 0x02, 0x03,
      ... sourceChainID,
      // input count:
      0x00, 0x00, 0x00, 0x01,
      // txID:
      0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81,
      0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01,
      0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
      0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
      // utxoIndex:
      0x00, 0x00, 0x00, 0x05,
      // assetID:
      ... fujiAssetId,
      // input:
      0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
      0x07, 0x5b, 0xcd, 0x15, 0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07,
    ]);

    it("Can sign a P->X Import transaction", async function() {
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Import"}],
        [{header:"Sending",body: "0.000012345 AVAX to fuji1cv6yz28qvqfgah34yw3y53su39p6kzzehw5pj3"}],
        [{header:"From",body: "P-chain"}],
        [{header:"Fee",body:"0.246901233 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = this.ava.signTransaction(
        BIPPath.fromString(pathPrefix),
        pathSuffixes.map(x => BIPPath.fromString(x, false)),
        importTxn(fujiPChainID),
      );
      await sigPromise;
      await ui.promptsPromise;
    });

    it("Can sign a C->X Import transaction", async function() {
        const ui = await flowMultiPrompt(this.speculos, [
          [{header:"Sign",body:"Import"}],
          [{header:"Sending",body: "0.000012345 AVAX to fuji1cv6yz28qvqfgah34yw3y53su39p6kzzehw5pj3"}],
          [{header:"From",body: "C-chain"}],
          [{header:"Fee",body:"0.246901233 AVAX"}],
          [{header:"Finalize",body:"Transaction"}],
        ]);
        const sigPromise = this.ava.signTransaction(
          BIPPath.fromString(pathPrefix),
          pathSuffixes.map(x => BIPPath.fromString(x, false)),
          importTxn(fujiCChainID),
        );
        await sigPromise;
        await ui.promptsPromise;
    });

    const exportTxn = destinationChainID => Buffer.from([
      // Codec ID
      0x00, 0x00,
      // base tx:
      0x00, 0x00, 0x00, 0x04,

      0x00, 0x00, 0x00, 0x05,
      // blockchainID: (fuji)
      0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c,
      0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
      0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6,
      0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,

      0x00, 0x00, 0x00, 0x01,
      ... fujiAssetId,
      0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01,
      0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e,
      0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46, 0x1c, 0x89,
      0x43, 0xab, 0x08, 0x59, 0x00, 0x00, 0x00, 0x01,
      0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81,
      0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01,
      0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
      0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
      0x00, 0x00, 0x00, 0x05,
      ... fujiAssetId,
      0x00, 0x00, 0x00, 0x05,
      0x00, 0x00, 0x00, 0x00, 0x07, 0x5b, 0xcd, 0x15,
      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07,
      0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
      0x00, 0x01, 0x02, 0x03,
      ... destinationChainID,
      // outs[] count:
      0x00, 0x00, 0x00, 0x01,
      // assetID:
      ... fujiAssetId,
      // output:
      0x00, 0x00, 0x00, 0x07,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x51, 0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78,
      0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2,
      0x6d, 0x55, 0xa9, 0x55
    ]);

    it("Can sign a X->P Export transaction", async function() {
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Export"}],
        [{header:"Transfer",body: "0.000012345 AVAX to fuji1cv6yz28qvqfgah34yw3y53su39p6kzzehw5pj3"}],
        [{header:"X to P chain",body:"0.000012345 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
        [{header:"Fee",body:"0.123432099 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = this.ava.signTransaction(
        BIPPath.fromString(pathPrefix),
        pathSuffixes.map(x => BIPPath.fromString(x, false)),
        exportTxn(fujiPChainID),
      );
      await sigPromise;
      await ui.promptsPromise;
    });

    it("Can sign a X->C Export transaction", async function() {
      const ui = await flowMultiPrompt(this.speculos, [
        [{header:"Sign",body:"Export"}],
        [{header:"Transfer",body: "0.000012345 AVAX to fuji1cv6yz28qvqfgah34yw3y53su39p6kzzehw5pj3"}],
        [{header:"X to C chain",body:"0.000012345 AVAX to fuji12yp9cc0melq83a5nxnurf0nd6fk4t224unmnwx"}],
        [{header:"Fee",body:"0.123432099 AVAX"}],
        [{header:"Finalize",body:"Transaction"}],
      ]);
      const sigPromise = this.ava.signTransaction(
        BIPPath.fromString(pathPrefix),
        pathSuffixes.map(x => BIPPath.fromString(x, false)),
        exportTxn(fujiCChainID),
      );
      await sigPromise;
      await ui.promptsPromise;
    });

  });
});

async function checkSignHash(this_, pathPrefix, pathSuffixes, hash) {
  const prompts = await flowAccept(
    this_.speculos,
    signHashPrompts(
      "111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000",
      pathPrefix,
    ),
  );
  const sigs = await this_.ava.signHash(
    BIPPath.fromString(pathPrefix),
    pathSuffixes.map(x => BIPPath.fromString(x, false)),
    Buffer.from(hash, "hex"),
  );
  await prompts.promptsMatch;

  expect(sigs).to.have.keys(pathSuffixes);

  for (suffix in sigs) {
    const sig = sigs.get(suffix);
    expect(sig).to.have.length(65);

    await flowAccept(this_.speculos);
    const key = (await this_.ava.getWalletExtendedPublicKey(pathPrefix + "/" + suffix)).public_key;
    const recovered = recover(Buffer.from(hash, 'hex'), sig.slice(0, 64), sig[64], false);
    expect(recovered).is.equalBytes(key);
  }
}

async function signTransaction(
  ava,
  pathPrefix,
  pathSuffixes,
  fieldOverrides = {},
) {
  const assetId = Buffer.from([
    0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
    0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
    0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
    0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa, // 32-byte asset ID
  ]);

  const fields = {
    ...{
      codecId: Buffer.from([0x00, 0x00]),
      typeId: Buffer.from([0x00, 0x00, 0x00, 0x00]),
      networkId: Buffer.from([0x00, 0x00, 0x00, 0x05]),
      extraEndBytes: Buffer.from([]),
      inputAssetId: assetId,
      inputTypeId: Buffer.from([0x00, 0x00, 0x00, 0x05]),
      outputAssetId: assetId,
      outputTypeId: Buffer.from([0x00, 0x00, 0x00, 0x07]),
      outputAmount: Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39]),
      inputAmount: Buffer.from([0x00, 0x00, 0x00, 0x00, 0x07, 0x5b, 0xcd, 0x15]),
    },
    ...fieldOverrides,
  }

  const transferrableOutput = Buffer.concat([
      fields.outputAssetId,
      fields.outputTypeId,
      fields.outputAmount,
      Buffer.from([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, // locktime
        0x00, 0x00, 0x00, 0x01, // threshold
        0x00, 0x00, 0x00, 0x01, // number of addresses (modified from reference)
        0x51, 0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78,
        0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2,
        0x6d, 0x55, 0xa9, 0x55, // address 1
        // part of reference serialiazation transaction but we reject multi-address outputs
        // 0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e,
        // 0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46, 0x1c, 0x89,
        // 0x43, 0xab, 0x08, 0x59, // address 2
      ]),
  ]);

  const transferrableInput = Buffer.concat([
    Buffer.from([
      0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81,
      0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01,
      0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
      0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00, // TX ID
      0x00, 0x00, 0x00, 0x05, // UTXO index
    ]),
    fields.inputAssetId,
    fields.inputTypeId,
    fields.inputAmount,
    Buffer.from([
      0x00, 0x00, 0x00, 0x02, // number of address indices
      0x00, 0x00, 0x00, 0x03, // address index 1
      0x00, 0x00, 0x00, 0x07, // address index 2
    ]),
  ]);

  const txn = Buffer.concat([
    fields.codecId,
    fields.typeId,
    fields.networkId,
    Buffer.from([
      // blockchainID: (fuji)
      0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c,
      0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
      0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6,
      0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,
      // number of outputs:
      0x00, 0x00, 0x00, 0x01,
    ]),
    fields.transferrableOutput ? fields.transferrableOutput : transferrableOutput,
    Buffer.from([
      // number of inputs:
      0x00, 0x00, 0x00, 0x01,
    ]),
    transferrableInput,
    Buffer.from([
      // Memo length:
      0x00, 0x00, 0x00, 0x04,
      // Memo:
      0x00, 0x01, 0x02, 0x03,
    ]),
    fields.extraEndBytes,
  ]);

  return await ava.signTransaction(
    BIPPath.fromString(pathPrefix),
    pathSuffixes.map(x => BIPPath.fromString(x, false)),
    txn,
  );
}

async function expectSignFailure(speculos, ava, fields, prompts=undefined) {
  try {
    const ui = prompts && prompts.length > 0
      ? await flowMultiPrompt(speculos, prompts, "Next", "Next")
      : undefined;
    await signTransaction(ava, "44'/9000'/0'", ["0/0"], fields);
    if (ui) await ui.promptsPromise;
    throw "Signing should have been rejected";
  } catch (e) {
    expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
    expect(e).has.property('statusText', 'UNKNOWN_ERROR');
  }
}

async function checkSignTransactionResult(ava, sig, pathPrefix, pathSuffixes) {
  expect(sig).to.have.property('hash');
  expect(sig).to.have.property('signatures');

  expect(sig.hash).to.have.length(32);
  expect(sig.signatures).to.have.length(pathSuffixes.length);
  expect(sig.signatures).to.have.keys(pathSuffixes);

  for (suffix in sig.signatures) {
    const sig = sigs.get(suffix);
    expect(sig).to.have.length(65);

    const prompts = flowAccept(this_.speculos);
    const key = (await ava.getWalletExtendedPublicKey(pathPrefix + "/" + suffix)).public_key;
    await prompts;
    const recovered = recover(Buffer.from(hash, 'hex'), sig.slice(0, 64), sig[64], false);
    expect(recovered).is.equalBytes(key);
  }
}
