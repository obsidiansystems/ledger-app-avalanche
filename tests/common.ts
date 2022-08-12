import fc from 'fast-check';

import createHash from "create-hash";
import chai from 'chai';
import chai_bytes from 'chai-bytes';
export const { expect } = chai.use(chai_bytes);
export { default as BIPPath } from "bip32-path";
import { default as BIPPath } from "bip32-path";
import secp256k1 from 'bcrypto/lib/secp256k1';
import Transport from "./transport";
import Ava from "hw-app-avalanche";
import Axios from 'axios';
export const { recover } = secp256k1;

export const baseUrl = "http://localhost:5000";

export const transportOpen = async () => {
  return await Transport.open(`${baseUrl}/apdu`);
}

export const makeAva = async () => {
  const transport = await transportOpen();
  return new Ava(transport);
};

export const APP_VERSION: string = process.env.APPVERSION || (() => { throw "app version unknown"; })();

export const ignoredScreens: string[] = [
  "W e l c o m e",
  "Cancel", "Working...", "Exit",
  "Avalanche", APP_VERSION,
]

export const setAcceptAutomationRules =
  async () => await setAutomationRules(defaultAcceptAutomationRules);

export const setAutomationRules = async function(rules) {
  await Axios.post(`${baseUrl}/automation`, {
    version: 1,
    rules: rules,
  });
}

export const pressAndReleaseBothButtons = [
  [ "button", 1, true ],
  [ "button", 2, true ],
  [ "button", 2, false ],
  [ "button", 1, false ],
];

export const pressAndReleaseSingleButton = (button) => [
  [ "button", button, true ],
  [ "button", button, false ],
];

export const defaultAcceptAutomationRules = [
  ... ignoredScreens.map(txt => { return { "text": txt, "actions": [] } }),
  {
    "y": 17,
    "actions": []
  },
  {
    "text": "Next",
    "actions": pressAndReleaseBothButtons,
  },
  {
    "text": "Accept",
    "actions": pressAndReleaseBothButtons,
  },
  {
    "text": "Confirm",
    "actions": pressAndReleaseBothButtons,
  },
  {
    // wild card, match any screen if we get this far
    "actions": pressAndReleaseSingleButton(2),
  },
];

export const defaultRejectAutomationRules = [
  ... ignoredScreens.map(txt => { return { "text": txt, "actions": [] } }),
  {
    "y": 17,
    "actions": []
  },
  {
    "text": "Next",
    "actions": pressAndReleaseBothButtons,
  },
  {
    "text": "Reject",
    "actions": pressAndReleaseBothButtons,
  },
  {
    // wild card, match any screen if we get this far
    "actions": pressAndReleaseSingleButton(2),
  },
];

type Event = { x: number, y: number, text: string };

export const processPrompts = function(prompts: Event[]): Screen[] {
  let i = prompts.filter((a : any) => !ignoredScreens.includes(a["text"])).values();
  let {done, value} = i.next();
  let header = "";
  let body = "";
  let rv = [];
  let regexp = /^(.*) \(([0-9]*)\/([0-9]*)\)$/;
  while(!done) {
    if(value["y"] == 3) {
      let m = value["text"].match(regexp);
      let cleanM = m && m[1] || value["text"]
      if(cleanM != header || m[2] == "1") {
        if(header || body) rv.push({ header, body });
        header = cleanM;
        body = "";
      }
    } else if(value["y"] == 17) {
      body += value["text"];
    } else if (value["y"] == 19 && value["text"] == "Next") {
      rv.push({ header: "Next", body });
      header = "";
      body = "";
    } else {
      if(header || body) rv.push({ header, body });
      if(value["text"] != "Accept" && value["text"] != "Reject") {
        rv.push(value);
      }
      header = "";
      body = "";
    }
    ({done, value} = i.next());
  }
  return rv;
}


export const deleteEvents = async () => await Axios.delete(`${baseUrl}/events`);

export const sendCommand = async function<A>(command : (Ava) => Promise<A>): Promise<A> {
  await setAcceptAutomationRules();
  await deleteEvents();
  let ava = await makeAva();

  //await new Promise(resolve => setTimeout(resolve, 100));

  let err = null;
  let res;

  try { res = await command(ava); } catch(e) {
    err = e;
  }

  //await new Promise(resolve => setTimeout(resolve, 100));

  if(err) {
    throw(err);
  } else {
    return res;
  }
};

export const getEvents = async (): Promise<Event[]> =>
  (await Axios.get(`${baseUrl}/events`)).data["events"];

export const sendCommandAndAccept = async <A>(command: (Ava) => A, prompts: undefined | Screen[]): Promise<A> => {
  await setAcceptAutomationRules();
  await deleteEvents();
  let ava = await makeAva();

  //await new Promise(resolve => setTimeout(resolve, 100));

  let err = null;
  let ret: A;
  try {
    ret = await command(ava);
  } catch(e) {
    err = e;
  }

  //await new Promise(resolve => setTimeout(resolve, 100));


  // expect(((await Axios.get(`${baseUrl}/events`)).data["events"] as [any]).filter((a : any) => !ignoredScreens.includes(a["text"]))).to.deep.equal(prompts);
  let err2 = null;
  if (prompts) {
    try {
      expect(processPrompts(await getEvents())).to.deep.equal(prompts);
    } catch (e) {
      err2 = e;
    }
  }

  if (err && !err2) {
    throw(err);
  } else if (!err && err2) {
    throw(err2);
  } else if (err && err2) {
    throw(new AggregateError([err, err2]));
  } else {
    return ret;
  }
}

// A couple of our screens use "bn" formatting for only one line of text and we
// don't have an icon so don't want "pn"; we need to know that there isn't
// going to be a body in those cases so we should send the screen.

export type Screen = { header: string, body: string }

export async function checkSignHash(this_, pathPrefix: string, pathSuffixes: string[], hash: string) {
  return await checkSignHash0(
    this_,
    BIPPath.fromString(pathPrefix),
    pathSuffixes.map(x => BIPPath.fromString(x, false)),
    hash,
  );
}

export async function checkSignHash0(this_, pathPrefix: BIPPath, pathSuffixes: BIPPath[], hash) {
  const sigs = await sendCommandAndAccept(async (ava : Ava) => {
    return await ava.signHash(
      pathPrefix,
      pathSuffixes,
      Buffer.from(hash, "hex"),
    );
  }, signHashPrompts(hash.toUpperCase(), pathPrefix));

  expect(sigs).to.have.keys(pathSuffixes.map(x => x.toString().slice(2)));

  for (const [suffix, sig] of sigs.entries()) {
    expect(sig).to.have.length(65);
    await sendCommand(async (ava : Ava) => {
      const key = (await ava.getWalletExtendedPublicKey(pathPrefix + "/" + suffix)).public_key;
      const recovered = recover(Buffer.from(hash, 'hex'), sig.slice(0, 64), sig[64], false);
      expect(recovered).is.equalBytes(key);
    });
  }
}

export async function checkSignTransaction(
  pathPrefix: string,
  pathSuffixes: string[],
  transaction: Buffer,
  prompts: Screen[],
) {
  const hash_expected = createHash("sha256").update(transaction).digest();
  const { hash, signatures } = await sendCommandAndAccept(async (ava : Ava) => {
    return await ava.signTransaction(
      BIPPath.fromString(pathPrefix),
      pathSuffixes.map(x => BIPPath.fromString(x, false)),
      transaction,
    );
  }, prompts);
  expect(hash).is.equalBytes(hash_expected);
  expect(signatures).to.have.keys(pathSuffixes);
  for (const [suffix, sig] of signatures.entries()) {
    expect(sig).to.have.length(65);
    await sendCommand(async (ava : Ava) => {
      const key = (await ava.getWalletExtendedPublicKey(pathPrefix + "/" + suffix)).public_key;
      const recovered = recover(hash, sig.slice(0, 64), sig[64], false);
      expect(recovered).is.equalBytes(key);
    });
  }
}

const chunkSize: number | null =
  process.env.PROMPT_MAX_BATCH_SIZE
  ? parseInt(process.env.PROMPT_MAX_BATCH_SIZE)
  : null;

export const chunkPrompts = (prompts: Screen[] ): Screen[] => {
  if (chunkSize == null)
    throw "PROMPT_MAX_BATCH_SIZE not set!";
  let chunked: Screen[] = [];
  for (let i = 0; i < prompts.length; i += chunkSize) {
    chunked = chunked.concat(prompts.slice(i, i + chunkSize));
    chunked.push({ header: "Next", body: "" })
  }
  return chunked;
}

const fcConfig = {
  interruptAfterTimeLimit: parseInt(process.env.GEN_TIME_LIMIT || "1000"),
  markInterruptAsFailure: false,
  numRuns: parseInt(process.env.GEN_NUM_RUNS || "100")
};

fc.configureGlobal(fcConfig);

export const signHashPrompts = (hash: string, pathPrefix: BIPPath): Screen[] => {
  return [
    {
      header:"Sign",
      body: "Hash"
    },
    {
      header:"DANGER!",
      body: "YOU MUST verify this manually!!!"
    },
    {
      header:"Derivation Prefix",
      body: pathPrefix.toString().slice(2) // avoid m/
    },
    {
      header:"Hash",
      body: hash
    },
    {
      header:"Are you sure?",
      body: "This is very dangerous!"
    },
  ];
};

export const finalizePrompt: Screen = {header: "Finalize", body: "Transaction"};
