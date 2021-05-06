const Transaction = require("@ethereumjs/tx").Transaction;
const Common = require("@ethereumjs/common").default;
const BN = require("bn.js");
const {bnToRlp, rlp} = require("ethereumjs-util");
const decode = require("rlp").decode;
const byContractAddress=require("@ledgerhq/hw-app-eth/erc20").byContractAddress;

const rawUnsignedTransaction = (chainId, unsignedTxParams) => {
    const common = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId });
    const unsignedTx = Transaction.fromTxData({...unsignedTxParams}, { common });

    // https://github.com/ethereumjs/ethereumjs-monorepo/issues/1188
    return rlp.encode([
        bnToRlp(unsignedTx.nonce),
        bnToRlp(unsignedTx.gasPrice),
        bnToRlp(unsignedTx.gasLimit),
        unsignedTx.to !== undefined ? unsignedTx.to.buf : Buffer.from([]),
        bnToRlp(unsignedTx.value),
        unsignedTx.data,
        bnToRlp(new BN(chainId)),
        Buffer.from([]),
        Buffer.from([]),
    ]);
};

const finalizePrompt = {header: "Finalize", body: "Transaction"};

const transferPrompts = (address, amount, fee) => [
    [{header: "Transfer",    body: amount + " to " + address}],
    [{header: "Fee",         body: fee}],
    [finalizePrompt]
];

const assetCallTransferPrompts = (assetID, address, amount) => [
    [{header: "Transfer",    body: amount + " of " + assetID + " to " + address}],
    [{header: "Maximum Fee", body: "47000000 GWEI"}],
    [finalizePrompt]
];

const assetCallDepositPrompts = (assetID, address, amount) => [
    [{header: "Deposit",     body: amount + " of " + assetID + " to " + address}],
    [{header: "Maximum Fee", body: "47000000 GWEI"}],
    [finalizePrompt]
];

const contractCallPrompts = (address, method, args) => {
    const methodPrompt   = {header: "Contract Call", body: method};
    const maxFeePrompt   = {header: "Maximum Fee",   body: "10229175 GWEI"};
    const argumentPrompts = args.map(([header,body]) => [{ header, body }]);

    return [].concat(
        [[methodPrompt]],
        argumentPrompts,
        [[maxFeePrompt],
         [finalizePrompt]]);
};

const contractDeployPrompts = (bytes, amount, fee, gas) => {
  const creationPrompt = {header: "Contract",          body: "Creation"};
  const gasPrompt      = {header: "Gas Limit",         body: gas};
  const fundingPrompt  = {header: "Funding Contract",  body: amount};
  const dataPrompt     = {header: "Data",              body: "0x60806040523480156200001157600080fd5b5060..."};
  const feePrompt      = {header: "Maximum Fee",       body: fee};
  return [].concat(
      [[creationPrompt, gasPrompt]],
      amount ? [[fundingPrompt]] : [],
      [[dataPrompt],
       [feePrompt],
       [finalizePrompt]
      ]
  );
};

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

const testDeploy = (chainId, withAmount) => async function () {
    this.timeout(8000);
    const [amountPrompt, amountHex] = withAmount ? ['0.000000001 nAVAX', '01'] : [null, '80'];
    await testSigning(this, chainId,
                      contractDeployPrompts(erc20presetMinterPauser.bytecodeHex, amountPrompt, '1428785900 GWEI', '3039970'),
                      ('f93873' + '03' + '856d6e2edc00' + '832e62e2' + '80' + amountHex
                       + ('b9385e' + erc20presetMinterPauser.bytecodeHex)
                       + '82a868' + '80' + '80'
                      )
                     );
};

const testUnrecognizedCalldataTx = (chainId, gasPrice, gasLimit, amountPrompt, amountHex, address, fee, calldata) => async function () {
    const tx = rawUnsignedTransaction(chainId, {
        nonce: '0x0a',
        gasPrice: '0x' + gasPrice,
        gasLimit: '0x' + gasLimit,
        to: '0x' + address,
        value: '0x' + amountHex,
        data: '0x' + calldata,
    });

    const prompts =
          [[{header: "Transfer",     body: amountPrompt + " to " + '0x' + address}],
           [{header: "Contract Data", body: "Is Present (unsafe)"}],
           [{header: "Maximum Fee",   body: fee}],
           [finalizePrompt]
          ];

    await testSigning(this, chainId, prompts, tx);
};

const testUnrecognizedCalldata = (calldata) => testUnrecognizedCalldataTx
(
    43112,
    '6d6e2edc00',
    '2dc6c0',
    "0.000000001 nAVAX", '01',
    "0102030400000000000000000000000000000002",
    '1410000000 GWEI',
    calldata
);

const testCall = (chainId, data, method, args) => async function () {
    const address = 'df073477da421520cf03af261b782282c304ad66';
    const tx = rawUnsignedTransaction(chainId, {
        nonce: '0x0a',
        gasPrice: '0x34630b8a00',
        gasLimit: '0xb197',
        to: '0x' + address,
        value: '0x0',
        data: '0x' + data,
    });

    await testSigning(this, chainId, contractCallPrompts('0x' + address, method, args), tx);
};

const testData = {
    address: {
        hex: '0000000000000000000000000101020203030404050506060707080809090a0a',
        prompt: '0101020203030404050506060707080809090a0a',
    },
    amount: {
        hex: '00000000000000000000000000000000000000000000000000000000000000aa',
        prompt: '0.00000017 GWEI',
    },
    bytes32: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',

    signatures: {
        transferFrom: 'f6153e09b51baa0e7564fd43034a9a540576d2aa869521c41a8247bc1ead5c9b570ae94343fcb0b5f1bce8d7b00f502544d3b723d799971d4a2b1b1a534d1e9c699000'
    }
};

describe("Eth app compatibility tests", async function () {
  this.timeout(3000);
  it('can get a key from the app with the ethereum ledgerjs module', async function() {
    const flow = await flowAccept(this.speculos);
    const dat = await this.eth.getAddress("44'/60'/0'/0/0", false, true);
    expect(dat.publicKey).to.equal("04ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
    expect(dat.address).to.equal("0xdad77910dbdfde764fc21fcd4e74d71bbaca6d8d");
    expect(dat.chainCode).to.equal("428489ee70680fa137392bc8399c4da9e39e92f058eb9e790f736142bba7e9d6");
    await flow.promptsPromise;
  });

  it('can sign a transaction via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43114,
                        transferPrompts('0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
                                        '12340000 nAVAX',
                                        '9870000 GWEI'
                                       ),
                        'ed01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080'
                       );
  });

  it('can sign a larger transaction via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43114,
                        transferPrompts('0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
                                        '238547462614852887054687704548455.429902335 nAVAX',
                                        '9870000 GWEI'),
                        'f83801856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c79529202bd072a24087400000f0fff0f0fff0f0fff8082a86a8080'
                       );
  });

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
  });

  it('can sign unrecognized calldata nonsense',
     testUnrecognizedCalldata('90000102030405060708090a0b0c0d0e0f')
    );

  it('can sign unrecognized calldata (borrow)',
     testUnrecognizedCalldata('a415bcad000000000000000000000000d3896bdd73e61a4275e27f660ddf095522f0a1d30000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f0f6da1852857d7789f68a28bba866671f3880d')
    );

  it('can sign unrecognized calldata (Pangolin AVAX/DAI swap)',
     testUnrecognizedCalldata('8a657e670000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000c7b9b39ab3081ac34fc4324e3f648b55528871970000000000000000000000000000000000000000000000000000017938dcec130000000000000000000000000000000000000000000000000000000000000002000000000000000000000000b31f66aa3c1e785363f0875a1b74e27b85fd66c7000000000000000000000000ba7deebbfc5fa1100fb055a87773e1e99cd3507a')
    );

  it('can sign unrecognized calldata (Pangolin AVAX/DAI swap 2)',
     testUnrecognizedCalldata('8a657e670000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000c7b9b39ab3081ac34fc4324e3f648b55528871970000000000000000000000000000000000000000000000000000017938e114be0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000b31f66aa3c1e785363f0875a1b74e27b85fd66c7000000000000000000000000ba7deebbfc5fa1100fb055a87773e1e99cd3507a')
    );

  it('can sign unrecognized calldata (Pangolin AVAX/DAI pool supply 1)',
     testUnrecognizedCalldata('f91b3f72000000000000000000000000ba7deebbfc5fa1100fb055a87773e1e99cd3507a000000000000000000000000000000000000000000000001a055690d9db800000000000000000000000000000000000000000000000000019e4080d9116900000000000000000000000000000000000000000000000000000d054d6a64e3c8e3000000000000000000000000c7b9b39ab3081ac34fc4324e3f648b55528871970000000000000000000000000000000000000000000000000000017938e009a0')
     );

  it('can sign unrecognized calldata (Pangolin AVAX/DAI pool supply 1)',
     testUnrecognizedCalldata('f91b3f72000000000000000000000000ba7deebbfc5fa1100fb055a87773e1e99cd3507a000000000000000000000000000000000000000000000001a055690d9db800000000000000000000000000000000000000000000000000019e4080d9116900000000000000000000000000000000000000000000000000000d01d2b83c13b9ab000000000000000000000000c7b9b39ab3081ac34fc4324e3f648b55528871970000000000000000000000000000000000000000000000000000017938e1fd96')
     );



  it('can sign a ERC20PresetMinterPauser pause contract call', testCall(43113, '8456cb59', 'pause', []));
  it('can sign a ERC20PresetMinterPauser unpause contract call', testCall(43113, '3f4ba83a', 'unpause', []));
  it('can sign a ERC20PresetMinterPauser burn contract call', testCall(43113, '42966c68' + testData.amount.hex, 'burn', [
      ["amount", testData.amount.prompt]
  ]));
  it('can sign a ERC20PresetMinterPauser mint contract call', testCall(43113, '40c10f19' + testData.address.hex + testData.amount.hex, 'mint', [
    ["to", '0x' + testData.address.prompt],
    ["amount", testData.amount.prompt]
  ]));

  it('can sign a ERC20PresetMinterPauser transferFrom contract call', testCall(43113, '23b872dd' + testData.address.hex + testData.address.hex + testData.amount.hex, 'transferFrom', [
    ["sender", '0x' + testData.address.prompt],
    ["recipient", '0x' + testData.address.prompt],
    ["amount", testData.amount.prompt]
  ]));

  it('can sign a ERC20PresetMinterPauser grantRole contract call', testCall(43113, '2f2ff15d' + testData.bytes32 + testData.address.hex, 'grantRole', [
      ["role", '0x' + testData.bytes32],
      ["account", '0x' + testData.address.prompt]
  ]));

  it('can sign a transaction deploying erc20 contract without funding', testDeploy(43112, false));
  it('can sign a transaction deploying erc20 contract with funding',    testDeploy(43112, true));

  it('can sign a transaction with assetCall via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112,
                        assetCallTransferPrompts('verma4Pa9biWKbjDGNsTXU47cYCyDSNGSU1iBkxucfVSFVXdv',
                                                 '0x41c9cc6fd27e26e70f951869fb09da685a696f0a',
                                                 '0x123456789abcdef'),
                        'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080'
                       );
  });

  it('can sign a transaction with assetCall deposit and funds via the ethereum ledgerjs module', async function() {
      await testSigning(this, 43112,
                        assetCallDepositPrompts('verma4Pa9biWKbjDGNsTXU47cYCyDSNGSU1iBkxucfVSFVXdv',
                                                '0x41c9cc6fd27e26e70f951869fb09da685a696f0a',
                                                '0x0'),
                        'f88001856d6e2edc00830186a094010000000000000000000000000000000000000280b85841c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000000000000000000d0e30db082a8688080'
                       );
  });

  it('can provide an ERC20 Token and sign with the ethereum ledgerjs module', async function() {
    const zrxInfo = byContractAddress("0xe41d2489571d322189246dafa5ebde1f4699f498");
    const result = await this.eth.provideERC20TokenInformation(zrxInfo);

    await testSigning(this, 43114,
                      transferPrompts('0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
                                      '12340000 nAVAX',
                                      '441000 GWEI'),
                      'ed018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080'
                     );
  });

  it('accepts apdu ending in the middle of parsing length of calldata', async function () {
    const prompts = contractCallPrompts('0x' + 'df073477da421520cf03af261b782282c304ad66',
                                        'transferFrom',
                                        [
                                            ["sender", '0x' + testData.address.prompt],
                                            ["recipient", '0x' + testData.address.prompt],
                                            ["amount", testData.amount.prompt]
                                        ]);
    const flow = await flowMultiPrompt(this.speculos, prompts);
    const apdu1 = 'e004000038' + '058000002c8000003c800000000000000000000000' + 'f88b0a8534630b8a0082b19794df073477da421520cf03af261b782282c304ad6680b8';
    const apdu2 = 'e00480006a' + '6423b872dd0000000000000000000000000101020203030404050506060707080809090a0a0000000000000000000000000101020203030404050506060707080809090a0a00000000000000000000000000000000000000000000000000000000000000aa82a8698080';
    const send = async (apduHex) => {
      const body = Buffer.from(apduHex, 'hex');
      return await this.speculos.exchange(body);
    };

    let rv = await send(apdu1);
    expect(rv).to.equalBytes("9000");
    rv = await send(apdu2);
    expect(rv).to.equalBytes(testData.signatures.transferFrom);
  });

  it('rejects transaction with incoherent tx/data length', async function () {
    const hex = 'e00400003d058000002c8000003c800600000000000000000000ed01856d6e2edc0782520894010000000000000000000000000000000000000200ffffffdadadada';
    const body = Buffer.from(hex, 'hex');
    const rv = await this.speculos.exchange(body);
    expect(rv).to.not.equalBytes("9000");
  });

  // TODO: something about these should-fail tests having no prompts causes the ones ran after it to fail

  it.skip('won\'t sign a transaction via a truely gargantuan number', async function() {
    try {
      await testSigning(this, 43114, [],
                        'f85c01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952b6002b0d072a024008740000000f0fff00f00fff0f00ff0f0fff00ff0f0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff8082a86a8080'
                       );
      throw "Signing should have been rejected";
    } catch (e) {
      expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
      expect(e).has.property('statusText', 'UNKNOWN_ERROR');
    }
  });

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
  });
});
