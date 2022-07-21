import {
  checkSignTransaction,
  chunkPrompts,
  expect,
  finalizePrompt,
  transportOpen,
  setAcceptAutomationRules,
  deleteEvents,
  processPrompts,
  getEvents,
  Screen,
} from "./common";

import Eth from '@ledgerhq/hw-app-eth';
import { Transaction } from "@ethereumjs/tx";
import { FeeMarketEIP1559Transaction as EIP1559Transaction } from "@ethereumjs/tx";
import Common from "@ethereumjs/common";
import { BN } from "bn.js";
import { bnToRlp, rlp } from "ethereumjs-util";
import { decode } from "rlp";
import { byContractAddressAndChainId } from "@ledgerhq/hw-app-eth/erc20";
import erc20presetMinterPauser from "./ERC20PresetMinterPauser";

const rawUnsignedLegacyTransaction = (chainId, unsignedTxParams) => {
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

const makeEth = async () => {
  const transport = await transportOpen();
  return new Eth(transport);
};

const rawUnsignedEIP1559Transaction = (chainId, unsignedTxParams) => {
  const common = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId }, 'london');

  const unsignedTx = EIP1559Transaction.fromTxData({...unsignedTxParams}, { common });


  // https://github.com/ethereumjs/ethereumjs-monorepo/issues/1188
  return unsignedTx.getMessageToSign(false);
};

const transferPrompts = (address, amount, fee) => chunkPrompts([
  {header: "Transfer",    body: amount + " to " + address},
  {header: "Fee",          body: fee},
]).concat([finalizePrompt]);

const assetCallTransferPrompts = (assetID, address, amount) => chunkPrompts([
  {header: "Transfer",    body: amount + " of " + assetID + " to " + address},
  {header: "Maximum Fee", body: "47000000 GWEI"},
]).concat([finalizePrompt]);

const assetCallDepositPrompts = (assetID, address, amount) => chunkPrompts([
  {header: "Deposit",     body: amount + " of " + assetID + " to " + address},
  {header: "Maximum Fee", body: "47000000 GWEI"},
]).concat([finalizePrompt]);

const contractCallPrompts = (method, argumentPrompts) => {
    const methodPrompt   = {header: "Contract Call", body: method};
    const maxFeePrompt   = {header: "Maximum Fee",   body: "10229175 GWEI"};

    return chunkPrompts([methodPrompt, ...argumentPrompts, maxFeePrompt])
       .concat([finalizePrompt]);
};

const contractDeployPrompts = (amount, fee, gas) => {
  const creationPrompt = {header: "Contract",          body: "Creation"};
  const gasPrompt      = {header: "Gas Limit",         body: gas};
  const fundingPrompt  = {header: "Funding Contract",  body: amount};
  const dataPrompt     = {header: "Data",              body: "0x60806040523480156200001157600080fd5b5060..."};
  const feePrompt      = {header: "Maximum Fee",       body: fee};
  return chunkPrompts(amount
    ? [creationPrompt, gasPrompt, fundingPrompt, dataPrompt, feePrompt]
    : [creationPrompt, gasPrompt, dataPrompt, feePrompt]
  )
    .concat([finalizePrompt]);
};

export const sendCommand = async function<A>(command : (Eth) => Promise<A>): Promise<A> {
  await setAcceptAutomationRules();
  await deleteEvents();
  let eth = await makeEth();

  //await new Promise(resolve => setTimeout(resolve, 100));

  let err = null;
  let res;

  try { res = await command(eth); } catch(e) {
    err = e;
  }

  //await new Promise(resolve => setTimeout(resolve, 100));

  if(err) {
    throw(err);
  } else {
    return res;
  }
}

export const sendCommandAndAccept = async <A>(command: (Eth) => A, prompts: undefined | Screen[]): Promise<A> => {
  await setAcceptAutomationRules();
  await deleteEvents();
  let eth = await makeEth();

  //await new Promise(resolve => setTimeout(resolve, 100));

  let err = null;
  let ret: A;
  try {
    ret = await command(eth);
  } catch(e) {
    err = e;
  }

  //await new Promise(resolve => setTimeout(resolve, 100));


  // expect(((await Axios.get(`${baseUrl}/events`)).data["events"] as [any]).filter((a : any) => !ignoredScreens.includes(a["text"]))).to.deep.equal(prompts);
  if (prompts) {
    expect(processPrompts(await getEvents())).to.deep.equal(prompts);
  }

  if(err) {
    throw(err);
  } else {
    return ret;
  }
}

async function testLegacySigning(self, chainId, prompts, hexTx) {
  const ethTx = Buffer.from(hexTx, 'hex');

  const dat = await sendCommandAndAccept(async (eth : Eth) => {
    const resolution = null;
    return await eth.signTransaction("44'/60'/0'/0/0", hexTx, resolution);
  }, prompts);
  const chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId });
  const txnBufsDecoded: any = decode(ethTx).slice(0,6);
  const txnBufsMap = [dat.v, dat.r, dat.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex'));
  const txnBufs = txnBufsDecoded.concat(txnBufsMap);
  //const txnBufs = decode(ethTx).slice(0,6).concat([dat.v, dat.r, dat.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex')));
  const ethTxObj = Transaction.fromValuesArray(txnBufs, {common: chain});
  expect(ethTxObj.verifySignature()).to.equal(true);
  expect(ethTxObj.getSenderPublicKey()).to.equalBytes("ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
}

async function testEIP1559Signing(self, chainId, prompts: Screen[], hexTx) {
  const ethTx = Buffer.from(hexTx, 'hex');

  const dat = await sendCommandAndAccept(async (eth : Eth) => {
    const resolution = null;
    return await eth.signTransaction("44'/60'/0'/0/0", hexTx, resolution);
  }, prompts);
  const chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId }, 'london')
  // remove the first byte from the start of the ethtx, the transactionType that's indicating it's an eip1559 transaction
  const txnBufsDecoded: any = decode(ethTx.slice(1)).slice(0,9);
  const txnBufsMap = [dat.v, dat.r, dat.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex'))
  const txnBufs = txnBufsDecoded.concat(txnBufsMap);
  const ethTxObj = EIP1559Transaction.fromValuesArray(txnBufs, {common: chain});
  expect(ethTxObj.verifySignature()).to.equal(true);
  expect(ethTxObj.getSenderPublicKey()).to.equalBytes("ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
}

const testDeploy = (chainId, withAmount) => async function () {
    this.timeout(8000);
    const [amountPrompt, amountHex] = withAmount
      ? ['0.000000001 nAVAX', '01']
      : [null, '80'];
    await testLegacySigning(this, chainId,
      contractDeployPrompts(amountPrompt, '1428785900 GWEI', '3039970'),
      ('f93873' + '03' + '856d6e2edc00' + '832e62e2' + '80' + amountHex
       + ('b9385e' + erc20presetMinterPauser.bytecodeHex)
       + '82a868' + '80' + '80'
      )
    );
};

const testUnrecognizedCalldataTx = (chainId, gasPrice, gasLimit, amountPrompt, amountHex, address, fee, calldata) => async function () {
    const tx = rawUnsignedLegacyTransaction(chainId, {
        nonce: '0x0a',
        gasPrice: '0x' + gasPrice,
        gasLimit: '0x' + gasLimit,
        to: '0x' + address,
        value: '0x' + amountHex,
        data: '0x' + calldata,
    });

    const transferPrompt = {header: "Transfer",     body: amountPrompt + " to " + '0x' + address};
    const dataPrompt = {header: "Contract Data", body: "Is Present (unsafe)"};
    const maxFeePrompt = {header: "Maximum Fee",   body: fee};

    const prompts = chunkPrompts([transferPrompt, dataPrompt, maxFeePrompt])
      .concat([finalizePrompt]);
    const eth = await makeEth();

  await testLegacySigning(this, chainId, prompts, tx);
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
    const tx = rawUnsignedLegacyTransaction(chainId, {
        nonce: '0x0a',
        gasPrice: '0x34630b8a00',
        gasLimit: '0xb197',
        to: '0x' + address,
        value: '0x0',
        data: '0x' + data,
    });
    const eth = await makeEth();

  await testLegacySigning(this, chainId, contractCallPrompts(method, args), tx);
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
    const eth = await makeEth();
    const dat = await eth.getAddress("44'/60'/0'/0/0", false, true);
    expect(dat.publicKey).to.equal("04ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4");
    expect(dat.address).to.equal("0xdad77910dbdfde764fc21fcd4e74d71bbaca6d8d");
    expect(dat.chainCode).to.equal("428489ee70680fa137392bc8399c4da9e39e92f058eb9e790f736142bba7e9d6");
  });

  it('can sign a transaction via the ethereum ledgerjs module', async function() {
    await testLegacySigning(this, 43114,
      transferPrompts(
        '0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
        '0.01234 AVAX',
        '9870000 GWEI'),
      'ed01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080'
    );
  });

  it('can sign a larger transaction via the ethereum ledgerjs module', async function() {
    await testLegacySigning(this, 43114,
      transferPrompts(
        '0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
        '238547462614852887054687.704548455429902335 AVAX',
        '9870000 GWEI'),
      'f83801856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c79529202bd072a24087400000f0fff0f0fff0f0fff8082a86a8080'
    );
  });

    it('can sign an EIP1559 transaction via the ethereum ledgerjs module with call data', async function() {
      const chainId = 43112;
      const tx = rawUnsignedEIP1559Transaction(chainId, {
          // chainId: chainId is passed through,
          nonce: '0x0a',
          maxFeePerGas: '0x3400',
          maxPriorityFeePerGas: '0x' + '64',
          gasLimit: '0x' + 'ab',
          to: '0x' + '0102030400000000000000000000000000000002',
          value: '0x' + '1000',
          data: '0x' + '90000102030405060708090a0b0c0d0e0f',
          // accessList: use the default
          // v: use the default
          // r: use the default
          // s: use the default
      });

      const transferPrompt = {header: "Transfer",     body: '0.000004096 nAVAX' + " to " + '0x' + '0102030400000000000000000000000000000002'};
      const dataPrompt = {header: "Contract Data", body: "Is Present (unsafe)"};
      const maxFeePrompt = {header: "Maximum Fee",   body: "0.002293452 GWEI"};
      const prompts = chunkPrompts([transferPrompt, dataPrompt, maxFeePrompt])
        .concat([finalizePrompt]);

      await testEIP1559Signing(this, chainId, prompts, tx);
    });

    it('can sign an EIP1559 transaction via the ethereum ledgerjs module without call data', async function() {
      const chainId = 43112;
      const tx = rawUnsignedEIP1559Transaction(chainId, {
          // chainId: chainId is passed through,
          nonce: '0x0a',
          maxFeePerGas: '0x3400',
          maxPriorityFeePerGas: '0x' + '64',
          gasLimit: '0x' + 'ab',
          to: '0x' + '0102030400000000000000000000000000000002',
          value: '0x' + '1000',
          // data: use the default
          // accessList: use the default
          // v: use the default
          // r: use the default
          // s: use the default
      });

      const transferPrompt = {header: "Transfer",     body: '0.000004096 nAVAX' + " to " + '0x' + '0102030400000000000000000000000000000002'};
      const feePrompt = {header: "Fee",   body: "0.002293452 GWEI"};
      const prompts = chunkPrompts([transferPrompt, feePrompt])
        .concat([finalizePrompt]);

      await testEIP1559Signing(this, chainId, prompts, tx);
    });

  it('Can sign an eip1559 transaction collected from metamask', async function() {
    this.timeout(8000);
    const chainId = 43112;
    // Collected from a metamask goerli transaction:
    const tx = Buffer.from('02f9018a82a868808506fc23ac008506fc23ac008316e3608080b90170608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220404e37f487a89a932dca5e77faaf6ca2de3b991f93d230604b1b8daaef64766264736f6c63430008070033c0', 'hex');

    const contractCreationPrompt = { header: 'Contract', body: 'Creation' };
    const gasLimitPrompt = { header: 'Gas Limit', body: '1500000' };
    const dataPrompt = { header: 'Data', body: '0x608060405234801561001057600080fd5b506101...' };
    const maxFeePrompt = { header: 'Maximum Fee', body: '90000000 GWEI' };
    const prompts = chunkPrompts([contractCreationPrompt, gasLimitPrompt, dataPrompt, maxFeePrompt])
      .concat([finalizePrompt]);
    await testEIP1559Signing(this, chainId, prompts, tx);
  });

  it('A call to assetCall with incorrect call data rejects', async function() {
    const resolution = null;
    try {
      const dat = await sendCommand(async (eth: Eth) =>
        await eth.signTransaction(
          "44'/60'/0'/0/0",
          'f83880856d6e2edc00832dc6c0940100000000000000000000000000000000000002019190000102030405060708090a0b0c0d0e0f82a8688080',
          resolution));
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
    { header: "amount", body: testData.amount.prompt }
  ]));
  it('can sign a ERC20PresetMinterPauser mint contract call', testCall(43113, '40c10f19' + testData.address.hex + testData.amount.hex, 'mint', [
    { header: "to",      body: '0x' + testData.address.prompt },
    { header: "amount", body: testData.amount.prompt }
  ]));

  it('can sign a ERC20PresetMinterPauser transferFrom contract call', testCall(43113, '23b872dd' + testData.address.hex + testData.address.hex + testData.amount.hex, 'transferFrom', [
    { header: "sender",    body: '0x' + testData.address.prompt },
    { header: "recipient", body: '0x' + testData.address.prompt },
    { header: "amount",    body: testData.amount.prompt },
  ]));

  it('can sign a ERC20PresetMinterPauser grantRole contract call', testCall(43113, '2f2ff15d' + testData.bytes32 + testData.address.hex, 'grantRole', [
    { header: "role",    body: '0x' + testData.bytes32 },
    { header: "account", body: '0x' + testData.address.prompt },
  ]));

  it('can sign a transaction deploying erc20 contract without funding', testDeploy(43112, false));
  it('can sign a transaction deploying erc20 contract with funding',    testDeploy(43112, true));

  it('can sign a transaction with assetCall via the ethereum ledgerjs module', async function() {
    await testLegacySigning(this, 43112,
      assetCallTransferPrompts(
        'verma4Pa9biWKbjDGNsTXU47cYCyDSNGSU1iBkxucfVSFVXdv',
        '0x41c9cc6fd27e26e70f951869fb09da685a696f0a',
        '0x123456789abcdef'),
      'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080'
    );
  });

  it('can sign a transaction with assetCall deposit and funds via the ethereum ledgerjs module', async function() {
    await testLegacySigning(this, 43112,
      assetCallDepositPrompts(
        'verma4Pa9biWKbjDGNsTXU47cYCyDSNGSU1iBkxucfVSFVXdv',
        '0x41c9cc6fd27e26e70f951869fb09da685a696f0a',
        '0x0'),
      'f88001856d6e2edc00830186a094010000000000000000000000000000000000000280b85841c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000000000000000000d0e30db082a8688080'
    );
  });

  it('can provide an ERC20 Token and sign with the ethereum ledgerjs module', async function() {
    const zrxInfo = byContractAddressAndChainId("0xe41d2489571d322189246dafa5ebde1f4699f498", 43114);
    if (zrxInfo !== undefined)
    {
      const result = await this.eth.provideERC20TokenInformation(zrxInfo);
    }

    await testLegacySigning(this, 43114,
      transferPrompts(
        '0x28ee52a8f3d6e5d15f8b131996950d7f296c7952',
        '0.01234 AVAX',
        '441000 GWEI'),
      'ed018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080'
    );
  });

  it('accepts apdu ending in the middle of parsing length of calldata', async function () {
    const transport = await transportOpen();
    await setAcceptAutomationRules();
    await deleteEvents();

    const prompts = contractCallPrompts(
      'transferFrom',
      [
        { header: "sender",    body: '0x' + testData.address.prompt },
        { header: "recipient", body: '0x' + testData.address.prompt },
        { header: "amount",    body: testData.amount.prompt },
      ]);
    const apdu1 = 'e004000038' + '058000002c8000003c800000000000000000000000' + 'f88b0a8534630b8a0082b19794df073477da421520cf03af261b782282c304ad6680b8';
    const apdu2 = 'e00480006a' + '6423b872dd0000000000000000000000000101020203030404050506060707080809090a0a0000000000000000000000000101020203030404050506060707080809090a0a00000000000000000000000000000000000000000000000000000000000000aa82a8698080';
    const send = async (apduHex) => {
      const body = Buffer.from(apduHex, 'hex');
      return await transport.exchange(body);
    };

    let rv = await send(apdu1);
    expect(rv).to.equalBytes("9000");
    rv = await send(apdu2);
    expect(rv).to.equalBytes(testData.signatures.transferFrom);
  });

  it('rejects transaction with incoherent tx/data length', async function () {
    const transport = await transportOpen();
    await setAcceptAutomationRules();
    await deleteEvents();

    const hex = 'e00400003d058000002c8000003c800600000000000000000000ed01856d6e2edc0782520894010000000000000000000000000000000000000200ffffffdadadada';
    const body = Buffer.from(hex, 'hex');
    const rv = await transport.exchange(body);
    expect(rv).to.not.equalBytes("9000");
  });

  // TODO: something about these should-fail tests having no prompts causes the ones ran after it to fail

  it('won\'t sign a transaction via a truely gargantuan number', async function() {
    try {
      await testLegacySigning(this, 43114, [],
                        'f85c01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952b6002b0d072a024008740000000f0fff00f00fff0f00ff0f0fff00ff0f0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff8082a86a8080'
                       );
      throw "Signing should have been rejected";
    } catch (e) {
      expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
      expect(e).has.property('statusText', 'UNKNOWN_ERROR');
    }
  });

  it('rejects assetCall with non-zero AVAX', async function() {
    try {
      await testLegacySigning(this, 43112, [],
                        'f87c01856d6e2edc00832dc6c094010000000000000000000000000000000000000201b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a0000000000000000000000000000000000000000000000000000000000001234582a8688080'
                       );
      throw "Signing should have been rejected";
    } catch (e) {
      expect(e).has.property('statusCode', 0x9405); // PARSE_ERROR
      expect(e).has.property('statusText', 'UNKNOWN_ERROR');
    }
  });

// TX DATA:
// {
//     "data": "0xa9059cbb0000000000000000000000009445c00ac0c0df04215ea5e2e581119273d2d9f80000000000000000000000000000000000000000000000056bc75e2d63100000",
//     "to": "0xc7AD46e0b8a400Bb3C915120d284AafbA8fc4735",
//     "from": "0x8B98D9523EB53D799943C2ceb9e6Cd57a0C90205",
//     "chainId": 4,
//     "gasLimit": {
//         "type": "BigNumber",
//         "hex": "0x879e"
//     },
//     "gasPrice": {
//         "type": "BigNumber",
//         "hex": "0x47869094"
//     },
//     "nonce": 1
// }
//
//
// FAILING ETH TRANSACTION: SEND


  //it.only('does not like the chain ID', async function() {
  //  this.timeout(199999999998);
  //  return await this.speculos.send(
  //    224,
  //    4,
  //    0,
  //    0,
  //    Buffer.from([
  //        5, 128, 0, 0, 44, 128, 0, 0, 60, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 248, 104, 1, 132, 71, 134, 144, 148, 130, 135, 158, 148, 199, 173, 70, 224, 184, 164, 0, 187, 60, 145, 81, 32, 210, 132, 170, 251, 168, 252, 71, 53, 128, 184, 68, 169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 69, 192, 10, 192, 192, 223, 4, 33, 94, 165, 226, 229, 129, 17, 146, 115, 210, 217, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 107, 199, 94, 45, 99, 16, 0, 0, 4, 128, 128
  //    ]),
  //  );
  //});
});
