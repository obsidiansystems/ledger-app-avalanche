import fc from 'fast-check';

import chai from 'chai';
import chai_bytes from 'chai-bytes';
export const { expect } = chai.use(chai_bytes);
export { default as BIPPath } from "bip32-path";
import secp256k1 from 'bcrypto/lib/secp256k1';
export const { recover } = secp256k1;

export async function flowAccept(speculos, expectedPrompts?, acceptPrompt="Accept") {
  return await automationStart(speculos, acceptPrompts(expectedPrompts, acceptPrompt));
}

// A couple of our screens use "bn" formatting for only one line of text and we
// don't have an icon so don't want "pn"; we need to know that there isn't
// going to be a body in those cases so we should send the screen.

const headerOnlyScreens = {
  "Configuration": 1,
  "Main menu": 1
};

type ManualIterator<A> = {
  next: () => Promise<A>,
  unsubscribe: () => void,
};

type InteractionFunc<A> = (speculos, screens?: ManualIterator<Screen>) => Promise<A>;

export type PromptsPromise<A> = { promptsPromise: Promise<A>, cancel: () => void };

/* State machine to read screen events and turn them into screens of prompts. */
export async function automationStart<A>(speculos, interactionFunc: InteractionFunc<A>):
  Promise<PromptsPromise<A>>
{
  // If this doesn't exist, we're running against a hardware ledger; just call
  // interactionFunc with no events iterator.
  if(!speculos.automationEvents) {
    return new Promise(r=>r({ promptsPromise: interactionFunc(speculos), cancel: () => {} }));
  }

  // This is so that you can just "await flowAccept(this.speculos);" in a test
  // without actually waiting for the prompts.  If we don't do this, you can
  // end up with two flowAccept calls active at once, causing issues.
  let subNum = speculos.handlerNum++;
  let promptLockResolve;
  let promptsLock=new Promise(r=>{promptLockResolve=r;});
  if(speculos.promptsEndPromise) {
    await speculos.promptsEndPromise;
  }
  speculos.promptsEndPromise = promptsLock; // Set ourselves as the interaction.

  // Make an async iterator we can push stuff into.
  let sendEvent: (Screen) => void;
  let sendPromise: Promise<Screen> = new Promise(r => { sendEvent = r; });
  let promptVal: Screen;

  let asyncEventIter: ManualIterator<Screen> = {
    next: async () => {
      promptVal=await sendPromise;
      sendPromise=new Promise(r => { sendEvent = r; });
      return promptVal;
    },
    unsubscribe: () => {
    },
  };

  // Sync up with the ledger; wait until we're on the home screen, and do some
  // clicking back and forth to make sure we see the event.
  // Then pass screens to interactionFunc./
  let readyPromise: Promise<PromptsPromise<A>> = syncWithLedger(speculos, asyncEventIter, interactionFunc);

  // Resolve our lock when we're done
  readyPromise.then(r=>r.promptsPromise.then(()=>{promptLockResolve(true);}));

  let header;
  let body;
  let screen: Screen;

  let subscript = speculos.automationEvents.subscribe({
    next: evt => {
      // Wrap up two-line prompts into one:
      if(evt.y == 3 && ! headerOnlyScreens[evt.text]) { // Configuration header is just one line
        header = evt.text;
        return; // The top line comes out first, so now wait for the next draw.
      } else {
        body = evt.text;
      }
      screen = { ...(header && {header}), body };
      if(process.env.DEBUG_SCREENS) console.log("SCREEN (" + subNum + "): " + JSON.stringify(screen));
      sendEvent(screen);
      body=undefined;
      header=undefined;
    }});

  const old = asyncEventIter.unsubscribe;
  asyncEventIter.unsubscribe = () => {
    old();
    subscript.unsubscribe();
  };

  // Send a rightward-click to make sure we get _an_ event and our state
  // machine starts.
  speculos.button("Rr");

  return readyPromise.then(r=>{r.cancel = ()=>{subscript.unsubscribe(); promptLockResolve(true);}; return r;});
}

async function syncWithLedger<A>(speculos, source: ManualIterator<Screen>, interactionFunc: InteractionFunc<A>):
 Promise<PromptsPromise<A>>
{
  let screen = await source.next();
  // Scroll to the end; we do this because we might have seen "Avalanche" when
  // we subscribed, but needed to send a button click to make sure we reached
  // this point.
  while(screen.body != "Quit") {
    speculos.button("Rr");
    screen = await source.next();
  }
  // Scroll back to "Avalanche", and we're ready and pretty sure we're on the
  // home screen.
  while(screen.header != "Avalanche") {
    speculos.button("Ll");
    screen = await source.next();
  }
  // And continue on to interactionFunc
  let interactFP = interactionFunc(speculos, source);
  return {
    promptsPromise: interactFP.finally(() => { source.unsubscribe(); }),
    cancel: async () => {}
  };
}

type Screen = { header: string, body: string }

async function readMultiScreenPrompt(speculos, source): Promise<Screen> {
  let header;
  let body;
  let screen = await source.next();
  let regexp = /^(.*) \(([0-9]*)\/([0-9]*)\)$/;
  let m = screen.header && screen.header.match(regexp);
  if (m) {
    header = m[1];
    body = screen.body;
    while(m[2] !== m[3]) {
      speculos.button("Rr");
      screen = await source.next();
      m = screen.header && screen.header.match(regexp);
      body = body + screen.body;
    }
    return { header: header, body: body };
  } else {
    return screen;
  }
}

export function acceptPrompts(expectedPrompts: undefined | Screen[], selectPrompt):
  InteractionFunc<{ promptsMatch?: true, expectedPrompts?, promptList?: Screen[] }>
{
  return async (speculos, screens) => {
    if(!screens) {
      // We're running against hardware, so we can't prompt but
      // should tell the person running the test what to do.
      if (expectedPrompts) {
        console.log("Expected prompts: ");
        for (const p in expectedPrompts) {
          console.log("Prompt %d", p);
          console.log(expectedPrompts[p][3]);
          console.log(expectedPrompts[p][17]);
        }
      }
      console.log("Please %s this prompt", selectPrompt);
      return { expectedPrompts, promptsMatch: true };
    } else {
      let promptList = [];
      let done = false;
      let screen: Screen;
      while(!done && (screen = await readMultiScreenPrompt(speculos, screens))) {
        if(screen.body != selectPrompt && screen.body != "Reject") {
          promptList.push(screen);
        }
        if(screen.body !== selectPrompt) {
          speculos.button("Rr");
        } else {
          speculos.button("RLrl");
          done = true;
        }
      }

      if (expectedPrompts) {
        expect(promptList).to.deep.equal(expectedPrompts);
        return { promptList, promptsMatch: true };
      } else {
        return { promptList };
      }
    }
  };
}

export async function flowMultiPrompt(speculos, prompts, nextPrompt="Next", finalPrompt="Accept"): Promise<{ promptsPromise: Promise<true> }> {
  // We bounce off the home screen sometimes during this process
  const isHomeScreen = p => p.header == "Avalanche" || p.body == "Configuration" || p.body == "Quit";
  const appScreens = ps => ps.filter(p => !isHomeScreen(p));

  return await automationStart(speculos, async (speculos, screens): Promise<true> => {
    for (const p of prompts.slice(0,-1)) {
      const rp = (await acceptPrompts(undefined, nextPrompt)(speculos, screens)).promptList;
      expect(appScreens(rp)).to.deep.equal(p);
    }
    const rp = (await acceptPrompts(undefined, finalPrompt)(speculos, screens)).promptList;
    expect(appScreens(rp)).to.deep.equal(prompts[prompts.length-1]);
    return true;
  });
}

export const chunkPrompts = <A>(prompts: A[] ): A[][] => {
  const chunkSize = 5;
  let chunked = [];
  for (let i = 0; i < prompts.length; i += chunkSize) {
    chunked.push(prompts.slice(i, i + chunkSize));
  }
  return chunked;
}

const fcConfig = {
  interruptAfterTimeLimit: parseInt(process.env.GEN_TIME_LIMIT || "1000"),
  markInterruptAsFailure: false,
  numRuns: parseInt(process.env.GEN_NUM_RUNS || "100")
};

fc.configureGlobal(fcConfig);

export const signHashPrompts = (hash, pathPrefix): Screen[] => {
  return [
    {header:"Sign",body:"Hash"},
    {header:"DANGER!",body:"YOU MUST verify this manually!!!"},
    {header:"Derivation Prefix",body:pathPrefix},
    {header:"Hash",body:hash},
    {header:"Are you sure?",body:"This is very dangerous!"},
  ];
};

export const finalizePrompt: Screen = {header: "Finalize", body: "Transaction"};
