// ZeroByte Relay, Relay Protocol v1 (https://docs.zerobyte.cloud/protocol).
//
// A blind, quota-bound mailbox between two paired devices of one app. It files
// opaque envelopes by app, mailbox, direction and sequence and hands them back.
// It cannot open them: every key is derived on the devices from the link key
// they agreed when they paired, and none ever reaches the relay. It stores, per
// mailbox, the SHA-256 of one bearer token, the envelopes not yet read, and
// their sequence numbers. A mailbox nobody writes to for 30 days erases itself.
//
// Optional extensions, enabled per app (src/apps.js):
//
//   push     the reader of a direction registers with a push service; a writer
//            that asks for it gets the reader woken by one content-free push.
//            Providers are separate modules (APNs: src/apns/), see push.js
//   signal   a WebSocket that forwards opaque frames between the two sides
//            while both are online, so they can set up a direct connection
//            (WebRTC, ICE) and move heavy data without the relay
//   ice      short-lived STUN/TURN credentials for that direct connection
//
// This file is the whole protocol and knows nothing about where it runs. The
// Cloudflare Worker (cloudflare.js) and the self-hosted Node server (node/)
// give it storage, WebSocket upgrades, the sockets already open, and a clock.
//
// <app> is a registered app id (a whole UUIDv7). An unknown app, the bare host,
// an extension the app has not enabled, and every other path answer the same
// 404. Every error is JSON: {"error": "<code>", "status": <n>}.
//
//   PUT    /v1/<app>/mailbox/<id>                     claim (first bearer wins) or confirm
//   DELETE /v1/<app>/mailbox/<id>                     erase everything
//   PUT    /v1/<app>/mailbox/<id>/<p2c|c2p>/<seq>     store one envelope [X-Relay-Notify]
//   GET    /v1/<app>/mailbox/<id>/<p2c|c2p>?after=&limit=   envelopes after a sequence
//   HEAD   /v1/<app>/mailbox/<id>/<p2c|c2p>           X-Relay-Last only
//   DELETE /v1/<app>/mailbox/<id>/<p2c|c2p>?through=  drop what the reader has read
//   GET    /v1/<app>/mailbox/<id>/<p2c|c2p>/watch     WebSocket: sequence numbers only
//   PUT    /v1/<app>/mailbox/<id>/<p2c|c2p>/push      register for pushes (push)
//   DELETE /v1/<app>/mailbox/<id>/<p2c|c2p>/push      unregister (push)
//   GET    /v1/<app>/mailbox/<id>/signal/<primary|companion>   WebSocket (signal)
//   GET    /v1/<app>/mailbox/<id>/ice                 STUN/TURN servers (ice)

import { fromBase64url, toHex } from "./bytes.js";
import { NOTIFY, PUSH, openRegistration, parseRegistration, sealRegistration } from "./push.js";
import { iceServers } from "./ice.js";
import { take } from "./rate.js";

/** Relay Protocol v1 limits: what every app gets unless its profile says otherwise. */
export const DEFAULT_LIMITS = Object.freeze({
  // 1 MiB of plaintext plus the 38-byte envelope overhead.
  envelopeBytes: 1_048_576 + 38,
  minimumEnvelopeBytes: 38,
  mailboxBytes: 32 * 1_048_576,
  envelopesPerDirection: 64,
  fetchLimit: 16,
  idleMilliseconds: 30 * 24 * 60 * 60 * 1000,
});
/** The defaults, under their original name. */
export const LIMITS = DEFAULT_LIMITS;

export const WATCH = Object.freeze({
  socketsPerDirection: 8,
  // A watcher that sent "ping" this recently is awake: no push is needed.
  freshMilliseconds: 45_000,
});

export const SIGNAL = Object.freeze({
  frameBytes: 65_536,
});

/** The WebSocket subprotocol a watcher may offer, and the one the relay answers with. */
export const WATCH_PROTOCOL = "zerobyte.v1";
/** Browsers cannot set headers on a WebSocket; they offer the bearer as a subprotocol. */
export const BEARER_PROTOCOL_PREFIX = "zerobyte.bearer.";

const DIRECTIONS = { p2c: 1, c2p: 2 };
const SIDES = { primary: "companion", companion: "primary" };
const APP = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAILBOX = /^[0-9a-f]{32}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SEQUENCE = /^[1-9][0-9]{0,19}$/;
const MAX_SEQUENCE = 2n ** 64n - 1n;
// Storage is listed in pages this size, so no request holds more than 16
// envelopes in memory however large the app's quota is.
const PAGE = 16;
const DAY = 24 * 60 * 60 * 1000;

const HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  // The bearer travels in a header, never in a cookie, so any origin may call:
  // a page without the token gets nothing. Web clients need these to read the
  // protocol headers.
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Expose-Headers": "X-Relay-Last, X-Relay-More, Retry-After",
};

// Every error carries a small JSON body, so a browser that opens the host shows
// it instead of downloading an empty, untyped file. Clients read the status only.
export const ERRORS = Object.freeze({
  400: "bad_request",
  401: "unauthorized",
  402: "payment_required",
  403: "forbidden",
  404: "not_found",
  405: "method_not_allowed",
  409: "sequence_conflict",
  413: "envelope_too_large",
  426: "upgrade_required",
  429: "rate_limited",
  502: "upstream_unavailable",
  507: "mailbox_full",
});

export function reply(status, body = null, extra = {}) {
  if (status >= 400 && body === null) {
    const error = ERRORS[status] ?? "error";
    return new Response(JSON.stringify({ error, status }), {
      status,
      headers: { ...HEADERS, "Content-Type": "application/json; charset=utf-8", ...extra },
    });
  }
  return new Response(body, { status, headers: { ...HEADERS, ...extra } });
}

function limited(seconds) {
  return reply(429, null, { "Retry-After": String(seconds) });
}

export function isAppID(text) {
  return typeof text === "string" && APP.test(text);
}

function parseSequence(text) {
  if (typeof text !== "string" || !SEQUENCE.test(text)) return null;
  const value = BigInt(text);
  return value <= MAX_SEQUENCE ? value : null;
}

function pad(sequence) {
  return sequence.toString().padStart(20, "0");
}

/** SHA-256 of the 32 token bytes the bearer encodes (unpadded base64url). */
async function digest(token) {
  return toHex(await crypto.subtle.digest("SHA-256", fromBase64url(token)));
}

function sameText(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function offeredProtocols(request) {
  return (request.headers.get("Sec-WebSocket-Protocol") ?? "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

function isUpgrade(request) {
  return (request.headers.get("Upgrade") ?? "").toLowerCase() === "websocket";
}

/**
 * The bearer token: from `Authorization: Bearer`, or, on a WebSocket upgrade
 * only, from a `zerobyte.bearer.<token>` subprotocol. Null when malformed.
 */
export function bearer(request) {
  const auth = request.headers.get("Authorization") ?? "";
  if (auth.startsWith("Bearer ")) {
    const token = auth.slice(7);
    return TOKEN.test(token) ? token : null;
  }
  if (!isUpgrade(request)) return null;
  const offered = offeredProtocols(request).find((p) => p.startsWith(BEARER_PROTOCOL_PREFIX));
  const token = offered?.slice(BEARER_PROTOCOL_PREFIX.length);
  return token && TOKEN.test(token) ? token : null;
}

/** The clear envelope header: version, direction, UInt64 BE sequence. */
export function envelopeHeader(bytes) {
  if (bytes.length < DEFAULT_LIMITS.minimumEnvelopeBytes) return null;
  let sequence = 0n;
  for (let i = 2; i < 10; i += 1) sequence = (sequence << 8n) | BigInt(bytes[i]);
  return { version: bytes[0], direction: bytes[1], sequence };
}

/** `count(UInt32 BE)` then `length(UInt32 BE) ‖ bytes` per envelope. */
export function joinEnvelopes(envelopes) {
  const total = 4 + envelopes.reduce((sum, e) => sum + 4 + e.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint32(0, envelopes.length);
  let offset = 4;
  for (const envelope of envelopes) {
    view.setUint32(offset, envelope.length);
    out.set(envelope, offset + 4);
    offset += 4 + envelope.length;
  }
  return out;
}

/**
 * `/v1/<app>/mailbox/<id>[/<segment>[/<tail>]]`, or null for anything else,
 * including an app id that is well formed but not registered.
 */
export function route(pathname, apps) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length < 4 || parts.length > 6) return null;
  const [version, app, kind, mailbox, direction, tail] = parts;
  if (version !== "v1" || kind !== "mailbox") return null;
  if (!APP.test(app) || !Object.hasOwn(apps, app) || !MAILBOX.test(mailbox)) return null;
  return { app, mailbox, direction, tail };
}

/** An app's limits: its profile's, or the protocol defaults. */
export function limitsOf(apps, app) {
  return apps[app]?.limits ?? DEFAULT_LIMITS;
}

function featuresOf(apps, app) {
  return apps[app]?.features ?? {};
}

/**
 * What a request asks for, or null when the path does not exist for this app.
 * Methods are checked later, so a wrong method answers 405 rather than 404.
 */
export function operation(method, place, apps) {
  const { direction, tail } = place;
  const features = featuresOf(apps, place.app);
  if (direction === undefined) return "mailbox";
  if (Object.hasOwn(DIRECTIONS, direction)) {
    if (tail === undefined) return "direction";
    if (tail === "watch") return "watch";
    if (tail === "push") return features.push ? "push" : null;
    return parseSequence(tail) === null ? null : "put";
  }
  if (direction === "signal") {
    return features.signal && Object.hasOwn(SIDES, tail ?? "") ? "signal" : null;
  }
  if (direction === "ice") return features.ice && tail === undefined ? "ice" : null;
  return null;
}

/** The name a request is counted under. Never its mailbox or sequence. */
function usageName(method, kind) {
  switch (kind) {
    case "mailbox":
      return method === "PUT" ? "claim" : method === "DELETE" ? "erase" : "other";
    case "direction":
      return { GET: "fetch", HEAD: "last", DELETE: "prune" }[method] ?? "other";
    case "push":
      return method === "PUT" ? "register" : method === "DELETE" ? "unregister" : "other";
    default:
      return kind;
  }
}

/**
 * One data point: app, operation, status class, count and bytes. No mailbox,
 * token, sequence or IP address. Only relay.zerobyte.cloud binds `USAGE`; a
 * self-hosted relay counts nothing.
 */
export function count(env, app, name, status, bytes = 0) {
  if (!env.USAGE) return;
  try {
    env.USAGE.writeDataPoint({
      indexes: [app],
      blobs: [app, name, `${Math.floor(status / 100)}xx`],
      doubles: [1, bytes],
    });
  } catch {
    // Counting never fails a delivery.
  }
}

/**
 * The front door. `env` carries `APPS` (registered app ids), `MAILBOX` (a
 * namespace with `idFromName` and `get(id).fetch`), and optionally `USAGE`.
 */
export async function handle(request, env) {
  const place = route(new URL(request.url).pathname, env.APPS);
  if (!place) return reply(404);
  const kind = operation(request.method, place, env.APPS);
  if (!kind) return reply(404);
  if (request.method === "OPTIONS") {
    return reply(204, null, {
      "Access-Control-Allow-Methods": "GET, HEAD, PUT, DELETE",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Relay-Notify",
      "Access-Control-Max-Age": "86400",
    });
  }
  if (!bearer(request)) return reply(401);
  // One object per app and mailbox: two apps never share a mailbox.
  const stub = env.MAILBOX.get(env.MAILBOX.idFromName(`${place.app}/${place.mailbox}`));
  const response = await stub.fetch(request);
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  const bytes = Number.isFinite(declared) && declared > 0 ? declared : 0;
  count(env, place.app, usageName(request.method, kind), response.status, bytes);
  return response;
}

/**
 * One mailbox. State, under `ctx.storage`:
 *   meta          { digest, last: { p2c, c2p } (decimal strings), bytes, count: { p2c, c2p } }
 *   e:<dir>:<seq, 20 digits>   Uint8Array envelope
 *   push:<dir>    { iv, data }: the reader's push registration, sealed (push.js)
 *
 * `ctx` provides:
 *   storage       get, put, list, delete, deleteAll, getAlarm, setAlarm, deleteAlarm
 *   sockets(tag?) open WebSockets, optionally only those with a tag
 *   tags(socket)  the tags a socket was accepted with
 *   lastPing(socket)  when the socket last sent "ping", in ms, or null
 *   upgrade(request, tag, protocol) -> { response, socket }
 *   memory        an object that lives as long as the mailbox stays in memory
 *   waitUntil(promise)  keeps work running after the response (optional)
 *   now()         the clock (optional)
 *
 * Everything that is not a storage call (reading the body, hashing the token,
 * sealing a registration) happens before `meta` is read, so no other request
 * can change the mailbox between reading `meta` and writing it back.
 */
export class Mailbox {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.ctx.memory ??= {};
  }

  now() {
    return this.ctx.now?.() ?? Date.now();
  }

  async meta() {
    return (await this.ctx.storage.get("meta")) ?? null;
  }

  /** 0 when allowed, else the seconds to wait. */
  rate(name) {
    return take(this.ctx.memory, name, this.now());
  }

  async fetch(request) {
    const url = new URL(request.url);
    const place = route(url.pathname, this.env.APPS);
    const kind = place && operation(request.method, place, this.env.APPS);
    if (!kind) return reply(404);
    const limits = limitsOf(this.env.APPS, place.app);
    const token = bearer(request);
    if (!token) return reply(401);

    let body = null;
    if (request.method === "PUT") {
      const most = kind === "push" ? PUSH.registrationBytes : limits.envelopeBytes;
      const declared = Number(request.headers.get("Content-Length") ?? "0");
      if (declared > most) return reply(413);
      body = new Uint8Array(await request.arrayBuffer());
      if (body.length > most) return reply(413);
    }
    let sealed = null;
    if (kind === "push" && request.method === "PUT") {
      const registration = parseRegistration(body, this.env.PUSH);
      if (!registration) return reply(400);
      sealed = await sealRegistration(token, place.mailbox, place.direction, registration);
    }
    const tokenDigest = await digest(token);
    const meta = await this.meta();

    if (kind === "mailbox") {
      if (request.method === "PUT") return this.claim(body, meta, tokenDigest, limits);
      if (!meta || !sameText(meta.digest, tokenDigest)) return reply(401);
      if (request.method === "DELETE") return this.erase();
      return reply(405, null, { Allow: "PUT, DELETE" });
    }

    if (!meta || !sameText(meta.digest, tokenDigest)) return reply(401);
    const directionName = place.direction;

    switch (kind) {
      case "watch":
        return this.watch(request, directionName);
      case "signal":
        return this.signal(request, place.tail);
      case "ice":
        if (request.method !== "GET") return reply(405, null, { Allow: "GET" });
        return this.ice();
      case "push":
        if (request.method === "PUT") return this.register(directionName, sealed, limits);
        if (request.method === "DELETE") return this.unregister(directionName);
        return reply(405, null, { Allow: "PUT, DELETE" });
      case "put": {
        if (request.method !== "PUT") return reply(405, null, { Allow: "PUT" });
        // A hosted app over its plan stores nothing new; reading and pruning still work.
        if (this.env.APPS[place.app]?.status === "suspended") return reply(402);
        const notify = request.headers.get("X-Relay-Notify");
        if (notify !== null && !NOTIFY.includes(notify)) return reply(400);
        const wait = this.rate("write");
        if (wait) return limited(wait);
        const sequence = parseSequence(place.tail);
        const stored = await this.put(body, meta, directionName, sequence, limits);
        if (stored.status === 201 && notify) this.notify(place, directionName, notify, token);
        return stored;
      }
      default: {
        const wait = this.rate("read");
        if (wait) return limited(wait);
        switch (request.method) {
          case "GET":
            return this.list(url, meta, directionName, limits);
          case "HEAD":
            return reply(200, null, this.lastHeader(meta, directionName));
          case "DELETE":
            return this.prune(url, meta, directionName);
          default:
            return reply(405, null, { Allow: "GET, HEAD, DELETE" });
        }
      }
    }
  }

  lastHeader(meta, directionName) {
    const last = meta.last[directionName];
    return last ? { "X-Relay-Last": last } : {};
  }

  async claim(body, meta, tokenDigest, limits) {
    if (meta) {
      if (!sameText(meta.digest, tokenDigest)) return reply(403);
      // A confirmed claim is a heartbeat: it keeps an idle mailbox alive.
      await this.touch(limits);
      return reply(204);
    }
    // A claim names the digest of its own token, so a mistyped client never
    // locks a mailbox it cannot open again.
    let claimed = null;
    try {
      claimed = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return reply(400);
    }
    if (!sameText(claimed?.tokenDigest, tokenDigest)) return reply(400);
    await this.ctx.storage.put("meta", {
      digest: tokenDigest,
      last: {},
      bytes: 0,
      count: { p2c: 0, c2p: 0 },
    });
    await this.touch(limits);
    return reply(201);
  }

  /** Envelopes waiting in a direction. Mailboxes from before the counter are counted once. */
  async waiting(meta, directionName) {
    meta.count ??= {};
    if (typeof meta.count[directionName] === "number") return meta.count[directionName];
    const prefix = `e:${directionName}:`;
    let total = 0;
    let start;
    for (;;) {
      const page = await this.ctx.storage.list({ prefix, start, limit: PAGE });
      total += page.size;
      if (page.size < PAGE) break;
      start = [...page.keys()].at(-1) + "\u0000";
    }
    meta.count[directionName] = total;
    return total;
  }

  async put(bytes, meta, directionName, sequence, limits) {
    const header = envelopeHeader(bytes);
    const direction = DIRECTIONS[directionName];
    if (!header || header.version !== 1 || header.direction !== direction) return reply(400);
    if (header.sequence !== sequence) return reply(400);
    const last = BigInt(meta.last[directionName] ?? "0");
    if (sequence <= last) return reply(409, null, this.lastHeader(meta, directionName));

    const waiting = await this.waiting(meta, directionName);
    if (waiting >= limits.envelopesPerDirection) return reply(507);
    if (meta.bytes + bytes.length > limits.mailboxBytes) return reply(507);

    meta.last[directionName] = sequence.toString();
    meta.bytes += bytes.length;
    meta.count[directionName] = waiting + 1;
    await this.ctx.storage.put({ [`e:${directionName}:${pad(sequence)}`]: bytes, meta });
    await this.touch(limits);
    for (const socket of this.ctx.sockets(directionName)) {
      try {
        socket.send(sequence.toString());
      } catch {
        // A closed watcher fetches on its next connection.
      }
    }
    return reply(201);
  }

  async list(url, meta, directionName, limits) {
    const after = url.searchParams.get("after") ?? "0";
    const from = after === "0" ? 0n : parseSequence(after);
    if (from === null) return reply(400);
    const asked = Number(url.searchParams.get("limit") ?? limits.fetchLimit);
    const limit = Number.isInteger(asked) && asked > 0 ? Math.min(asked, limits.fetchLimit) : 0;
    if (limit === 0) return reply(400);
    const prefix = `e:${directionName}:`;
    const page = await this.ctx.storage.list({
      prefix,
      start: prefix + pad(from + 1n),
      limit: limit + 1,
    });
    const envelopes = [...page.values()].slice(0, limit).map((v) => new Uint8Array(v));
    return reply(200, joinEnvelopes(envelopes), {
      "Content-Type": "application/octet-stream",
      "X-Relay-More": page.size > limit ? "1" : "0",
      ...this.lastHeader(meta, directionName),
    });
  }

  async prune(url, meta, directionName) {
    const through = parseSequence(url.searchParams.get("through") ?? "");
    if (through === null) return reply(400);
    const prefix = `e:${directionName}:`;
    const end = prefix + pad(through + 1n);
    const waiting = await this.waiting(meta, directionName);
    let removed = 0;
    for (;;) {
      const page = await this.ctx.storage.list({ prefix, end, limit: PAGE });
      if (page.size === 0) break;
      for (const value of page.values()) meta.bytes -= value.byteLength ?? value.length;
      removed += page.size;
      await this.ctx.storage.delete([...page.keys()]);
      if (page.size < PAGE) break;
    }
    meta.bytes = Math.max(0, meta.bytes);
    meta.count[directionName] = Math.max(0, waiting - removed);
    await this.ctx.storage.put("meta", meta);
    return reply(204);
  }

  async erase() {
    for (const socket of this.ctx.sockets()) {
      try {
        socket.close(1000, "erased");
      } catch {
        // Already closed.
      }
    }
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
    return reply(204);
  }

  accept(request, tag) {
    if (!isUpgrade(request)) return { refused: reply(426) };
    const wait = this.rate("connect");
    if (wait) return { refused: limited(wait) };
    const offered = offeredProtocols(request);
    // Answer with the protocol name, never with the bearer subprotocol.
    const protocol = offered.includes(WATCH_PROTOCOL) ? WATCH_PROTOCOL : null;
    return this.ctx.upgrade(request, tag, protocol);
  }

  watch(request, directionName) {
    if (this.ctx.sockets(directionName).length >= WATCH.socketsPerDirection) return limited(60);
    const accepted = this.accept(request, directionName);
    return accepted.refused ?? accepted.response;
  }

  /** Is a reader of this direction watching and awake? Then it needs no push. */
  watched(directionName) {
    const now = this.now();
    return this.ctx.sockets(directionName).some((socket) => {
      const at = this.ctx.lastPing?.(socket);
      return typeof at === "number" && now - at < WATCH.freshMilliseconds;
    });
  }

  // ---- push ---------------------------------------------------------------

  async register(directionName, sealed, limits) {
    const wait = this.rate("register");
    if (wait) return limited(wait);
    await this.ctx.storage.put(`push:${directionName}`, sealed);
    await this.touch(limits);
    return reply(204);
  }

  async unregister(directionName) {
    await this.ctx.storage.delete([`push:${directionName}`]);
    return reply(204);
  }

  /**
   * Wakes the reader of a direction after a write that asked for it. Runs
   * after the response; never fails the write. Returns the work, for tests.
   */
  notify(place, directionName, kind, token) {
    const topic = featuresOf(this.env.APPS, place.app).push;
    const providers = this.env.PUSH;
    if (!topic || !providers || this.watched(directionName)) return null;
    if (this.rate(`push:${directionName}`)) return null;
    const key = `push:${directionName}`;
    const work = (async () => {
      const sealed = await this.ctx.storage.get(key);
      if (!sealed) return;
      let registration;
      try {
        registration = await openRegistration(token, place.mailbox, directionName, sealed);
      } catch {
        return;
      }
      // Checked again: it may have been stored before this provider was configured.
      const provider = providers[registration.service];
      if (!provider) return;
      const { service, tag, alert, ...rest } = registration;
      const fields = provider.parse(rest);
      if (!fields) return;
      const result = await provider.send(topic, { ...fields, tag, alert }, kind, this.now());
      count(this.env, place.app, "notify", result.status || 599);
      if (result.gone) {
        const current = await this.ctx.storage.get(key);
        if (current?.iv === sealed.iv) await this.ctx.storage.delete([key]);
      }
    })().catch(() => {});
    this.ctx.waitUntil?.(work);
    return work;
  }

  // ---- signal -------------------------------------------------------------

  signal(request, side) {
    const tag = `signal:${side}`;
    if (!isUpgrade(request)) return reply(426);
    // One socket per side: a reconnect replaces the one before it.
    const previous = this.ctx.sockets(tag);
    const accepted = this.accept(request, tag);
    if (accepted.refused) return accepted.refused;
    for (const old of previous) {
      try {
        old.close(4000, "replaced");
      } catch {
        // Already closed.
      }
    }
    const peers = this.ctx.sockets(`signal:${SIDES[side]}`);
    if (peers.length) {
      for (const socket of [accepted.socket, ...peers]) {
        try {
          socket.send("peer 1");
        } catch {
          // The other side will hear it when it reconnects.
        }
      }
    }
    return accepted.response;
  }

  ice() {
    if (!this.env.ICE) return reply(404);
    const wait = this.rate("ice");
    if (wait) return limited(wait);
    return iceServers(this.env.ICE, this.now()).then(
      (servers) =>
        reply(200, JSON.stringify(servers), { "Content-Type": "application/json; charset=utf-8" }),
      () => reply(502),
    );
  }

  sideOf(socket) {
    const tag = (this.ctx.tags?.(socket) ?? []).find((t) => t.startsWith("signal:"));
    return tag ? tag.slice("signal:".length) : null;
  }

  webSocketMessage(socket, message) {
    const side = this.sideOf(socket);
    // Watchers only listen ("ping" is answered before it gets here).
    if (!side) return socket.close(1003, "listen only");
    // Signal frames are binary and opaque: the devices seal them.
    if (typeof message === "string") return socket.close(1003, "binary only");
    const size = message.byteLength ?? message.length;
    if (size > SIGNAL.frameBytes) return socket.close(1009, "too big");
    if (this.rate(`signal:${side}`)) return socket.close(1008, "rate limited");
    for (const peer of this.ctx.sockets(`signal:${SIDES[side]}`)) {
      try {
        peer.send(message);
      } catch {
        // Gone; the sender hears "peer 0".
      }
    }
    return undefined;
  }

  webSocketClose(socket, code) {
    try {
      socket.close(code === 1005 || code === 1006 ? 1000 : code, "closed");
    } catch {
      // Already closed.
    }
    const side = this.sideOf(socket);
    if (!side) return;
    const others = this.ctx.sockets(`signal:${side}`).filter((s) => s !== socket);
    if (others.length) return;
    for (const peer of this.ctx.sockets(`signal:${SIDES[side]}`)) {
      try {
        peer.send("peer 0");
      } catch {
        // Already closed.
      }
    }
  }

  /**
   * Restarts the idle timer. The alarm is set a day past the idle time and
   * moved only once it falls short, so most writes cost no alarm write: a
   * mailbox is erased between `idle` and `idle` plus one day after its last
   * write or claim.
   */
  async touch(limits = DEFAULT_LIMITS) {
    const due = this.now() + limits.idleMilliseconds;
    const current = await this.ctx.storage.getAlarm();
    if (current !== null && current >= due) return;
    await this.ctx.storage.setAlarm(due + DAY);
  }

  async alarm() {
    await this.erase();
  }
}
