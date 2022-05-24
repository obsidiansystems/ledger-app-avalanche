import Transport from "@ledgerhq/hw-transport";
import { TransportError } from "@ledgerhq/errors";

import axios from "axios";
import { log } from "@ledgerhq/logs";

export default class HttpTransport extends Transport {
  static list = (): any => Promise.resolve([]);
  static listen = (_observer: any) => ({
    unsubscribe: () => {},
  });
  static async open(url: string, timeout?: number): Promise<Transport> {
    // await HttpTransport.check(url, timeout);
    return new HttpTransport(url);
  }

  url: string;

  constructor(url: string) {
    super();
    this.url = url;
  }

  async exchange(apdu: Buffer): Promise<Buffer> {
    const apduHex = apdu.toString("hex");
    log("apdu", "=> " + apduHex);
    const response = await axios({
      method: "POST",
      url: this.url,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      data: {
        data: apduHex,
      }
    });

    if (response.status !== 200) {
      throw (TransportError(
        "failed to communicate to server. code=" + response.status,
        "HttpTransportStatus" + response.status
      ) as any);
    }

    const body = (await response.data) as any;
    if (body.error) throw body.error;
    log("apdu", "<= " + JSON.stringify(body));
    return Buffer.from(body.data, "hex");
  }

  setScrambleKey() {}

  close(): Promise<void> {
    return Promise.resolve();
  }
}
