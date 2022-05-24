import Avalanche from 'hw-app-avalanche';
import Eth from '@ledgerhq/hw-app-eth';
import HidTransport from '@ledgerhq/hw-transport-node-hid';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import { SpawnOptions, spawn } from 'child_process';

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
          '--sdk', '2.1',
        ], speculosProcessOptions);
        console.log("Speculos started");
      }
    }
  },

  afterAll: async function () {
    if (this.speculosProcess) {
      this.speculosProcess.kill();
    }
  },
};
