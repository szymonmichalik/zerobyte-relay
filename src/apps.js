// Registered apps. The key is the app id, the first segment of the path after
// /v1/: a whole UUIDv7, lowercase. It is not a secret, since it ships inside
// the app; the bearer token per mailbox is what authorises. It keeps unknown
// clients out and each app's mailboxes and usage counts apart.
//
// Configure with RELAY_APPS: a comma-separated list of ids, each optionally
// followed by `=name`:
//
//   RELAY_APPS="01a1601b-fa85-7d58-b2a2-1416e0a6b054=derived,0192...=notes"
//
// Generate an id with `npm run app-id`.

import { isAppID } from "./core.js";

export function appsFrom(text) {
  const apps = {};
  for (const entry of String(text ?? "").split(/[,\s]+/).filter(Boolean)) {
    const [id, name = ""] = entry.split("=");
    if (!isAppID(id)) throw new Error(`RELAY_APPS: "${id}" is not a lowercase UUIDv7`);
    apps[id] = Object.freeze({ name });
  }
  return Object.freeze(apps);
}

/** A fresh UUIDv7 (RFC 9562 §5.7): 48-bit Unix milliseconds, then randomness. */
export function newAppID(now = Date.now(), random = crypto.getRandomValues(new Uint8Array(10))) {
  const bytes = new Uint8Array(16);
  let ms = BigInt(now);
  for (let i = 5; i >= 0; i -= 1) {
    bytes[i] = Number(ms & 0xffn);
    ms >>= 8n;
  }
  bytes.set(random, 6);
  bytes[6] = 0x70 | (bytes[6] & 0x0f);
  bytes[8] = 0x80 | (bytes[8] & 0x3f);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)]
    .join("-");
}
