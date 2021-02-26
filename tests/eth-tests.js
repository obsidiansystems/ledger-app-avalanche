Transaction = require("@ethereumjs/tx").Transaction;
Common = require("@ethereumjs/common").default;
decode = require("rlp").decode;
byContractAddress=require("@ledgerhq/hw-app-eth/erc20").byContractAddress;

const transferPrompts = (address, amount) => [
    [{header: "Transfer",    body: amount + " to " + address}],
    [{header: "Fee",         body: "9870000 GWEI"}],
    [{header: "Finalize",    body: "Transaction"}]
];
const assetCallTransferPrompts = (assetID, address, amount) => [
    [{header: "Transfer",    body: amount + " of " + assetID + " to " + address}],
    [{header: "Maximum Fee", body: "47000000 GWEI"}],
    [{header: "Finalize",    body: "Transaction"}]
];
const assetCallDepositPrompts = (assetID, address, amount) => [
    [{header: "Deposit",     body: amount + " of " + assetID + " to " + address}],
    [{header: "Maximum Fee", body: "47000000 GWEI"}],
    [{header: "Finalize",    body: "Transaction"}]
];

async function testSigning(self, chainId, prompts, hexTx) {
  const ethTx = Buffer.from(hexTx, 'hex');
  const flow = await flowMultiPrompt(self.speculos, prompts);
  const chainParams = { common: Common.forCustomChain('mainnet', { networkId: 1, chainId }, 'istanbul')};

  const dat = await self.eth.signTransaction("44'/60'/0'/0/0", ethTx);
  chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId });
  txnBufs = decode(ethTx).slice(0,6).concat([dat.v, dat.r, dat.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex')));
  ethTxObj = Transaction.fromValuesArray(txnBufs, {common: chain});
  expect(ethTxObj.verifySignature()).to.equal(true);
  expect(ethTxObj.getSenderPublicKey()).to.equalBytes("ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
  await flow.promptsPromise;
}

describe("Eth app compatibility tests", () => {
  it('can get a key from the app with the ethereum ledgerjs module', async function() {
    const flow = await flowAccept(this.speculos);
    const dat = await this.eth.getAddress("44'/60'/0'/0/0", false, true);
    expect(dat.publicKey).to.equal("04ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
    expect(dat.address).to.equal("0xdad77910dbdfde764fc21fcd4e74d71bbaca6d8d");
    expect(dat.chainCode).to.equal("428489ee70680fa137392bc8399c4da9e39e92f058eb9e790f736142bba7e9d6");
    await flow.promptsPromise;
  })

  it('can sign a transaction via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43114,
                        transferPrompts('0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
                                        '12340000 nAVAX'),
                        'ed01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080'
                       );
  })

  it('A call to assetCall with incorrect call data rejects', async function() {
    try {
      const dat = await this.eth.signTransaction(
          "44'/60'/0'/0/0",
          'f83880856d6e2edc00832dc6c0940100000000000000000000000000000000000002019190000102030405060708090a0b0c0d0e0f82a8688080');
      throw "Signing should have been rejected";
    } catch (e) {
        expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
        expect(e).has.property('statusText', 'UNKNOWN_ERROR');
    }
  })

  it('can sign a transaction with calldata via the ethereum ledgerjs module', async function() {
    await testSigning(this, 43112,
        [[{header:"Transfer",      body: "0.000000001 nAVAX to 0x0102030400000000000000000000000000000002"}],
         [{header:"Contract Data", body: "Is Present (unsafe)"}],
         [{header:"Maximum Fee",   body: "1410000000 GWEI"}],
         [{header:"Finalize",      body: "Transaction"}]
        ],
        'f83880856d6e2edc00832dc6c0940102030400000000000000000000000000000002019190000102030405060708090a0b0c0d0e0f82a8688080');
  })

  it('can sign a transaction with assetCall via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112,
                        assetCallTransferPrompts('verma4Pa9biWKbjDGNsTXU47cYCyDSNGSU1iBkxucfVSFVXdv',
                                                 '0x41c9cc6fd27e26e70f951869fb09da685a696f0a',
                                                 '0x0123456789abcdef'),
                        'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080'
                       )
  })

  it('can sign a transaction with assetCall deposit and funds via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112,
                        assetCallDepositPrompts('verma4Pa9biWKbjDGNsTXU47cYCyDSNGSU1iBkxucfVSFVXdv',
                                                '0x41c9cc6fd27e26e70f951869fb09da685a696f0a',
                                                '0x0'),
                        'f88001856d6e2edc00830186a094010000000000000000000000000000000000000280b85841c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000000000000000000d0e30db082a8688080'
                       )
  });

  it('can provide an ERC20 Token and sign with the ethereum ledgerjs module', async function() {
    const flow = await flowMultiPrompt(this.speculos,
      [
        [{header:"Transfer", body: "12340000 nAVAX to 0x28ee52a8f3d6e5d15f8b131996950d7f296c7952"}],
        [{header:"Fee",      body: "441000 GWEI"}],
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

  // TODO: something about this test having no prompts causes the ones ran after it to fail
  it.skip('rejects assetCall with non-zero AVAX', async function() {
    try {
      await testSigning(this, 43112, [],
                        'f87c01856d6e2edc00832dc6c094010000000000000000000000000000000000000201b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a0000000000000000000000000000000000000000000000000000000000001234582a8688080'
                       );
      throw "Signing should have been rejected";
    } catch (e) {
      expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
      expect(e).has.property('statusText', 'UNKNOWN_ERROR');
    }
  })
});
