import fc from 'fast-check';
import * as chai from 'chai';
import 'chai-bytes';

export async function flowAccept(speculos, expectedPrompts, acceptPrompt="Accept") {
  return await automationStart(speculos, acceptPrompts(expectedPrompts, acceptPrompt));
}

// A couple of our screens use "bn" formatting for only one line of text and we
// don't have an icon so don't want "pn"; we need to know that there isn't
// going to be a body in those cases so we should send the screen.

const headerOnlyScreens = {
  "Configuration": 1,
  "Main menu": 1
};

/* State machine to read screen events and turn them into screens of prompts. */
export async function automationStart(speculos, interactionFunc) {
  // If this doesn't exist, we're running against a hardware ledger; just call
  // interactionFunc with no events iterator.
  if(!speculos.automationEvents) {
    return new Promise(r=>r({ promptsPromise: interactionFunc(speculos) }));
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
  let sendEvent;
  let sendPromise=new Promise(r=>{sendEvent = r;});
  let asyncEventIter = {
    next: async ()=>{
      promptVal=await sendPromise;
      sendPromise=new Promise(r=>{sendEvent = r;});
      return promptVal;
    },
    peek: async ()=>{
      return await sendPromise;
    }
  };

  // Sync up with the ledger; wait until we're on the home screen, and do some
  // clicking back and forth to make sure we see the event.
  // Then pass screens to interactionFunc.
  let readyPromise = syncWithLedger(speculos, asyncEventIter, interactionFunc);

  // Resolve our lock when we're done
  readyPromise.then(r=>r.promptsPromise.then(()=>{promptLockResolve(true);}));

  let header;
  let body;

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

  asyncEventIter.unsubscribe = () => { subscript.unsubscribe(); };

  // Send a rightward-click to make sure we get _an_ event and our state
  // machine starts.
  speculos.button("Rr");

  return readyPromise.then(r=>{r.cancel = ()=>{subscript.unsubscribe(); promptLockResolve(true);}; return r;});
}

async function syncWithLedger(speculos, source, interactionFunc) {
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
  // Sink some extra homescreens to make us a bit more durable to failing tests.
  while(await source.peek().header == "Avalanche" || await source.peek().body == "Configuration" || await source.peek().body == "Quit") {
    await source.next();
  }
  // And continue on to interactionFunc
  let interactFP = interactionFunc(speculos, source);
  return { promptsPromise: interactFP.finally(() => { source.unsubscribe(); }) };
}

async function readMultiScreenPrompt(speculos, source) {
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

export function acceptPrompts(expectedPrompts, selectPrompt) {
  return async (speculos, screens) => {
    if(!screens) {
      // We're running against hardware, so we can't prompt but
      // should tell the person running the test what to do.
      if (expectedPrompts) {
        console.log("Expected prompts: ");
        for (p in expectedPrompts) {
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

export async function flowMultiPrompt(speculos, prompts, nextPrompt="Next", finalPrompt="Accept") {
  // We bounce off the home screen sometimes during this process
  const isHomeScreen = p => p.header == "Avalanche" || p.body == "Configuration" || p.body == "Quit";
  const appScreens = ps => ps.filter(p => !isHomeScreen(p));

  return await automationStart(speculos, async (speculos, screens) => {
    for (p of prompts.slice(0,-1)) {
      const rp = (await acceptPrompts(undefined, nextPrompt)(speculos, screens)).promptList;
      expect(appScreens(rp)).to.deep.equal(p);
    }
    const rp = (await acceptPrompts(undefined, finalPrompt)(speculos, screens)).promptList;
    expect(appScreens(rp)).to.deep.equal(prompts[prompts.length-1]);
    return true;
  });
}

export const chunkPrompts = (prompts) => {
  const chunkSize = 5;
  let chunked = [];
  for (let i = 0; i < prompts.length; i += chunkSize) {
    chunked.push(prompts.slice(i, i + chunkSize));
  }
  return chunked;
}

const fcConfig = {
  interruptAfterTimeLimit: parseInt(process.env.GEN_TIME_LIMIT || 1000),
  markInterruptAsFailure: false,
  numRuns: parseInt(process.env.GEN_NUM_RUNS || 100)
};

fc.configureGlobal(fcConfig);

export const signHashPrompts = (hash, pathPrefix) => {
  return [
    {header:"Sign",body:"Hash"},
    {header:"DANGER!",body:"YOU MUST verify this manually!!!"},
    {header:"Derivation Prefix",body:pathPrefix},
    {header:"Hash",body:hash},
    {header:"Are you sure?",body:"This is very dangerous!"},
  ];
};
export const BIPPath = require("bip32-path");
export const { recover } = require('bcrypto/lib/secp256k1');
export const { expect } = chai.use(require('chai-bytes'));
