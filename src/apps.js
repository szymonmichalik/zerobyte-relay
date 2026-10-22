// Registered apps. The key is the app id, the first segment of the path after
// /v1/: a whole UUIDv7, lowercase. It is not a secret, since it ships inside
// the app; the bearer token per mailbox is what authorises. It keeps unknown
// clients out and each app's mailboxes and usage counts apart.
//
// Configure with RELAY_APPS: a comma-separated list of ids, each optionally
// followed by `=name` and then `;option` settings:
//
//   RELAY_APPS="01a1601b-fa85-7d58-b2a2-1416e0a6b054=derived,0192...=chat;push=com.example.chat;signal;ice;envelopes=1024"
//
// Options (all optional; without them an app gets the Relay Protocol v1 defaults):
//
//   push=<topic>       push notifications; for APNs the topic is the bundle id, FCM ignores it
//   signal             the signal socket, for direct connections between devices
//   ice                STUN/TURN credentials for those connections
//   envelopes=<n>      envelopes waiting per direction, 16 … 4096 (default 64)
//   mailbox=<MiB>      mailbox size, 1 … 256 (default 32)
//   envelope=<KiB>     largest plaintext, 1 … 1024 (default 1024)
//   idle=<days>        idle mailbox erased after, 1 … 365 (default 30)
//
// Generate an id with `npm run app-id`.

import { DEFAULT_LIMITS, isAppID } from "./core.js";
import { isTopic } from "./push.js";

const INTEGER = /^[1-9][0-9]{0,5}$/;

function bounded(id, option, text, low, high, source) {
  if (!INTEGER.test(text ?? "") || Number(text) < low || Number(text) > high) {
    throw new Error(`${source}: ${id}: ${option} must be a whole number from ${low} to ${high}`);
  }
  return Number(text);
}

function profile(id, name, options, source = "RELAY_APPS", status = "active") {
  const limits = { ...DEFAULT_LIMITS };
  const features = { push: null, signal: false, ice: false };
  const seen = new Set();
  for (const option of options) {
    const [key, value] = option.split(/=(.*)/s, 2);
    if (seen.has(key)) throw new Error(`${source}: ${id}: ${key} is set twice`);
    seen.add(key);
    switch (key) {
      case "push":
        if (!isTopic(value)) throw new Error(`${source}: ${id}: push needs a bundle id, as push=com.example.app`);
        features.push = value;
        break;
      case "signal":
      case "ice":
        if (value !== undefined) throw new Error(`${source}: ${id}: ${key} takes no value`);
        features[key] = true;
        break;
      case "envelopes":
        limits.envelopesPerDirection = bounded(id, key, value, 16, 4096, source);
        break;
      case "mailbox":
        limits.mailboxBytes = bounded(id, key, value, 1, 256, source) * 1_048_576;
        break;
      case "envelope":
        limits.envelopeBytes = bounded(id, key, value, 1, 1024, source) * 1024 + 38;
        break;
      case "idle":
        limits.idleMilliseconds = bounded(id, key, value, 1, 365, source) * 24 * 60 * 60 * 1000;
        break;
      default:
        throw new Error(`${source}: ${id}: unknown option "${key}"`);
    }
  }
  if (limits.envelopeBytes > limits.mailboxBytes) {
    throw new Error(`${source}: ${id}: envelope is larger than mailbox`);
  }
  return Object.freeze({ name, status, limits: Object.freeze(limits), features: Object.freeze(features) });
}

/**
 * One app's profile from options written as in RELAY_APPS (`push=…;signal`).
 * `status` is "active", or "suspended" to refuse its writes with 402.
 */
export function appProfile(id, name, options, status = "active") {
  if (!isAppID(id)) throw new Error(`registry: "${id}" is not a lowercase UUIDv7`);
  if (status !== "active" && status !== "suspended") throw new Error(`registry: ${id}: unknown status`);
  return profile(id, name, String(options ?? "").split(";").filter(Boolean), "registry", status);
}

export function appsFrom(text) {
  const apps = {};
  for (const entry of String(text ?? "").split(/[,\s]+/).filter(Boolean)) {
    const [head, ...options] = entry.split(";");
    const [id, name = ""] = head.split("=");
    if (!isAppID(id)) throw new Error(`RELAY_APPS: "${id}" is not a lowercase UUIDv7`);
    if (Object.hasOwn(apps, id)) throw new Error(`RELAY_APPS: ${id} is listed twice`);
    apps[id] = profile(id, name, options.filter(Boolean));
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
