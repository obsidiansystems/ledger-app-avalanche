Transaction = require("@ethereumjs/tx").Transaction;
Common = require("@ethereumjs/common").default;
decode = require("rlp").decode;
byContractAddress=require("@ledgerhq/hw-app-eth/erc20").byContractAddress;

    async function testSigning(self, chainId, address, amount, hexTx) {
      const ethTx = Buffer.from(hexTx, 'hex');
      const flow = await flowMultiPrompt(self.speculos,
        [
          [{header:"Transfer", body: amount + " to " + address}],
          [{header:"Finalize", body: "Transaction"}]
        ]);
      const chainParams = { common: Common.forCustomChain('mainnet', { networkId: 1, chainId }, 'istanbul')};

      const dat = await self.eth.signTransaction("44'/60'/0'/0/0", ethTx);
      chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId });
      txnBufs = decode(ethTx).slice(0,6).concat([dat.v, dat.r, dat.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex')));
      ethTxObj = Transaction.fromValuesArray(txnBufs, {common: chain});
      console.error(ethTxObj.getMessageToVerifySignature());
      console.error(ethTxObj.serialize().toString('hex'));
      expect(ethTxObj.verifySignature()).to.equal(true);
      expect(ethTxObj.getSenderPublicKey()).to.equalBytes("ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
      await flow.promptsPromise;
    }

describe.only("Eth app compatibility tests", () => {
  it('can get a key from the app with the ethereum ledgerjs module', async function() {
    const flow = await flowAccept(this.speculos);
    const dat = await this.eth.getAddress("44'/60'/0'/0/0", false, true);
    expect(dat.publicKey).to.equal("04ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
    expect(dat.address).to.equal("0xdad77910dbdfde764fc21fcd4e74d71bbaca6d8d");
    expect(dat.chainCode).to.equal("428489ee70680fa137392bc8399c4da9e39e92f058eb9e790f736142bba7e9d6");
    await flow.promptsPromise;
  })

  it.only('can sign a transaction with the ethereum ledgerjs module', async function() {
      await testSigning(this, 43114, '0x28ee52a8f3d6e5d15f8b131996950d7f296c7952', '12340000',
                        'ed018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080'
                       );
  })
  it.only('can sign a transaction with the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112, '0x0100000000000000000000000000000000000006', '0.000000001',
                        'f83880856d6e2edc00832dc6c0940100000000000000000000000000000000000006019190000102030405060708090a0b0c0d0e0f82a8688080'
                       );
  })
  it.only('can sign a transaction with the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112, '0x0100000000000000000000000000000000000006', '0',
                        'f88001856d6e2edc00832dc6c094010000000000000000000000000000000000000680b85841c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000000000000000011d0e30db082a8688080'
                       )
  })
  it.only('can sign a transaction with the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112, '0x0100000000000000000000000000000000000006', '8',
                        'f88501856d6e2edc00832dc6c09401000000000000000000000000000000000000068501dcd65000b85841c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000000000000000008d0e30db082a8688080'
                       )
  });
  it('can provide an ERC20 Token and sign with the ethereum ledgerjs module', async function() {
    const flow = await flowMultiPrompt(this.speculos,
      [
        [{header:"Transfer", body: "60563456.369098752 to 0x28ee52a8f3d6e5d15f8b131996950d7f296c7952"}],
        [{header:"Finalize", body: "Transaction"}]
      ]);
    ethTx = Buffer.from('ed018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080', 'hex');
    const zrxInfo = byContractAddress("0xe41d2489571d322189246dafa5ebde1f4699f498");
    const result = await this.eth.provideERC20TokenInformation(zrxInfo);
    const dat = await this.eth.signTransaction("44'/60'/0'/0/0", ethTx);

    chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId: 43114 });
    txnBufs = decode(ethTx).slice(0,6).concat([dat.v, dat.r, dat.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex')));
    ethTxObj = Transaction.fromValuesArray(txnBufs, {common: chain});
    expect(ethTxObj.verifySignature()).to.equal(true);
    expect(ethTxObj.getSenderPublicKey()).to.equalBytes("ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
    await flow.promptsPromise;

  });
  it.skip('can sign a personal message with the ethereum ledgerjs module', async function() {
    const res = await this.eth.signPersonalMessage("44'/60'/0'/0/0", "aabbccddeeff");
  });
})
