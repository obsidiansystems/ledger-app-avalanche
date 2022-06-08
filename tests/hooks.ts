import Avalanche from 'hw-app-avalanche';
import Eth from '@ledgerhq/hw-app-eth';
import HidTransport from '@ledgerhq/hw-transport-node-hid';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import { SpawnOptions, spawn } from 'child_process';

const APDU_PORT = 9999;
const BUTTON_PORT = 8888;
const AUTOMATION_PORT = 8899;

let stdoutVal: string = "";
let stderrVal: string = "";

export const mochaHooks = {
  beforeAll: async function (this: Mocha.Context) { // Need 'function' to get 'this'
    this.timeout(10000); // We'll let this wait for up to 10 seconds to get a speculos instance.
    if (process.env.LEDGER_LIVE_HARDWARE) {
      this.speculos = await HidTransport.create();
      this.speculos.button = console.log;
      console.log(this.speculos);
    } else {
      if (!process.env.USE_EXISTING_SPECULOS) {
        const speculosProcessOptions: SpawnOptions = process.env.SPECULOS_DEBUG ? {stdio:"inherit"} : {};
        this.speculosProcess = spawn('speculos', [
          process.env.LEDGER_APP,
          '--display', 'headless',
          '--button-port', '' + BUTTON_PORT,
          '--automation-port', '' + AUTOMATION_PORT,
          '--apdu-port', '' + APDU_PORT,
          '--sdk', '1.6',
        ], speculosProcessOptions);
        console.log("Speculos started");
      }
      while (this.speculos === undefined) { // Let the test timeout handle the bad case
        try {
          this.speculos = await SpeculosTransport.open({
            apduPort: APDU_PORT,
            buttonPort: BUTTON_PORT,
            automationPort: AUTOMATION_PORT,
          });
          if (process.env.MANUAL_BUTTON) {
            this.speculos.button = console.log;
          } else if (process.env.DEBUG_BUTTONS) {
            const subButton = this.speculos.button;
            this.speculos.button = btns => {
              console.log("Speculos Buttons: " + btns);
              return subButton(btns);
            };
          }
          if (process.env.DEBUG_SENDS) {
            this.speculos.subExchange = this.speculos.exchange;
            this.speculos.exchange = buff => {
              console.log("Speculos send: " + buff.toString('hex'));
              return this.speculos.subExchange(buff);
            };
          }
        } catch(e) {
          await new Promise(r => setTimeout(r, 500));
        }
      }
    }
    this.speculos.handlerNum=0;
    this.speculos.waitingQueue=[];
    this.ava = new Avalanche(this.speculos, "Avalanche", _ => { return; });
    this.eth = new Eth(this.speculos);

    this.flushStdio = (n) => () => {
        if (this.speculosProcess && this.speculosProcess.stdio[n])
            return this.speculosProcess.stdio[n].read();
        else
            return "";
    };
    this.flushStdout = this.flushStdio(1);
    this.flushStderr = this.flushStdio(2);
    this.readBuffers = () => {
        stdoutVal += (this.flushStdout() || "");
        stderrVal += (this.flushStderr() || "");
    };
  },

  afterAll: async function () {
    if (this.speculosProcess) {
      this.speculosProcess.kill();
    }
  },

  beforeEach: async function () {
    stdoutVal = "";
    stderrVal = "";
    this.flusher = setInterval(this.readBuffers, 100);
  },

  afterEach: async function () {
    clearInterval(this.flusher);
    this.readBuffers();
    const maxOutput = 5000;
    if (this.currentTest.state === 'failed') {
      console.log("SPECULOS STDOUT" + ":\n" + stdoutVal);
      console.log("SPECULOS STDERR" +
                  (stderrVal.length <= maxOutput
                   ? ":\n" + stderrVal
                   : (" (showing last " + maxOutput + " characters)" + ":\n" + stderrVal.slice(-maxOutput))));
    }
  }
};
