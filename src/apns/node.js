// APNs delivery on Node (part of the APNs module): one HTTP/2 session per APNs host, opened
// on first use and closed after a minute without a push.

import { connect } from "node:http2";

const IDLE_MILLISECONDS = 60_000;
const TIMEOUT_MILLISECONDS = 15_000;

export function http2Deliver() {
  const sessions = new Map();

  function session(origin) {
    const existing = sessions.get(origin);
    if (existing && !existing.closed && !existing.destroyed) return existing;
    const created = connect(origin);
    created.on("error", () => sessions.delete(origin));
    created.on("close", () => sessions.delete(origin));
    created.setTimeout(IDLE_MILLISECONDS, () => created.close());
    created.unref?.();
    sessions.set(origin, created);
    return created;
  }

  const deliver = ({ url, headers, body }) =>
    new Promise((resolve, reject) => {
      const target = new URL(url);
      const stream = session(target.origin).request({
        ":method": "POST",
        ":path": target.pathname,
        ...headers,
      });
      let status = 0;
      let text = "";
      stream.setEncoding("utf8");
      stream.setTimeout(TIMEOUT_MILLISECONDS, () => stream.close());
      stream.on("response", (h) => {
        status = Number(h[":status"]);
      });
      stream.on("data", (chunk) => {
        text += chunk;
      });
      stream.on("end", () => resolve({ status, body: text }));
      stream.on("error", reject);
      stream.end(body);
    });
  deliver.close = () => {
    for (const s of sessions.values()) s.close();
    sessions.clear();
  };
  return deliver;
}
