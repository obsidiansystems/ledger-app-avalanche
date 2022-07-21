import HidTransport from '@ledgerhq/hw-transport-node-hid';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import { SpawnOptions, spawn } from 'child_process';
import Axios from "axios";

let stdoutVal: string = "";
let stderrVal: string = "";
const baseUrl = "http://localhost:5000";

const flushStdio = (proc, n) => () => {
  if (proc && proc.stdio[n])
    return proc.stdio[n].read();
  else
    return "";
};

export const getEvents = async (): Promise<Event[]> =>
  (await Axios.get(`${baseUrl}/events`)).data["events"];

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
          '--sdk', '2.1',
        ], speculosProcessOptions);
        console.log("Speculos started");

        while(true) {
          try {
            await getEvents();
            break;
          } catch(e) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        }
      }
    }
    this.flushStdout = flushStdio(this.speculosProcess, 1);
    this.flushStderr = flushStdio(this.speculosProcess, 2);
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
