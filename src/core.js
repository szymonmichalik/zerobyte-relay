// ZeroByte Relay, Relay Protocol v1 (https://docs.zerobyte.cloud/protocol).
//
// A blind, quota-bound mailbox between two paired devices of one app. It files
// opaque envelopes by app, mailbox, direction and sequence and hands them back.
// It cannot open them: every key is derived on the devices from the link key
// they agreed when they paired, and none ever reaches the relay. It stores, per
// mailbox, the SHA-256 of one bearer token, the envelopes not yet read, and
// their sequence numbers. A mailbox nobody writes to for 30 days erases itself.
//
// This file is the whole protocol and knows nothing about where it runs. The
// Cloudflare Worker (cloudflare.js) and the self-hosted Node server (node/)
// give it the same three things: storage, an upgrade to a WebSocket, and the
// sockets already watching.
//
// <app> is a registered app id (a whole UUIDv7). An unknown app, the bare host
// and every other path answer the same 404. Every error is JSON:
// {"error": "<code>", "status": <n>}.
//
//   PUT    /v1/<app>/mailbox/<id>                     claim (first bearer wins) or confirm
//   DELETE /v1/<app>/mailbox/<id>                     erase everything
//   PUT    /v1/<app>/mailbox/<id>/<p2c|c2p>/<seq>     store one envelope
//   GET    /v1/<app>/mailbox/<id>/<p2c|c2p>?after=&limit=   envelopes after a sequence
//   HEAD   /v1/<app>/mailbox/<id>/<p2c|c2p>           X-Relay-Last only
//   DELETE /v1/<app>/mailbox/<id>/<p2c|c2p>?through=  drop what the reader has read
//   GET    /v1/<app>/mailbox/<id>/<p2c|c2p>/watch     WebSocket: sequence numbers only

export const LIMITS = Object.freeze({
  // 1 MiB of plaintext plus the 38-byte envelope overhead.
  envelopeBytes: 1_048_576 + 38,
  minimumEnvelopeBytes: 38,
  mailboxBytes: 32 * 1_048_576,
  envelopesPerDirection: 64,
  fetchLimit: 16,
  idleMilliseconds: 30 * 24 * 60 * 60 * 1000,
});

/** The WebSocket subprotocol a watcher may offer, and the one the relay answers with. */
export const WATCH_PROTOCOL = "zerobyte.v1";
/** Browsers cannot set headers on a WebSocket; they offer the bearer as a subprotocol. */
export const BEARER_PROTOCOL_PREFIX = "zerobyte.bearer.";

const DIRECTIONS = { p2c: 1, c2p: 2 };
const APP = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAILBOX = /^[0-9a-f]{32}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SEQUENCE = /^[1-9][0-9]{0,19}$/;
const MAX_SEQUENCE = 2n ** 64n - 1n;

const HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  // The bearer travels in a header, never in a cookie, so any origin may call:
  // a page without the token gets nothing. Web clients need these to read the
  // two protocol headers.
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Expose-Headers": "X-Relay-Last, X-Relay-More",
};

// Every error carries a small JSON body, so a browser that opens the host shows
// it instead of downloading an empty, untyped file. Clients read the status only.
export const ERRORS = Object.freeze({
  400: "bad_request",
  401: "unauthorized",
  403: "forbidden",
  404: "not_found",
  405: "method_not_allowed",
  409: "sequence_conflict",
  413: "envelope_too_large",
  426: "upgrade_required",
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
  const binary = atob(token.replaceAll("-", "+").replaceAll("_", "/") + "=");
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
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
  if ((request.headers.get("Upgrade") ?? "").toLowerCase() !== "websocket") return null;
  const offered = offeredProtocols(request).find((p) => p.startsWith(BEARER_PROTOCOL_PREFIX));
  const token = offered?.slice(BEARER_PROTOCOL_PREFIX.length);
  return token && TOKEN.test(token) ? token : null;
}

/** The clear envelope header: version, direction, UInt64 BE sequence. */
export function envelopeHeader(bytes) {
  if (bytes.length < LIMITS.minimumEnvelopeBytes) return null;
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
 * `/v1/<app>/mailbox/<id>[/<direction>[/<tail>]]`, or null for anything else,
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

/** What a request is, for the usage counters: never its mailbox or sequence. */
function operation(request, place) {
  if (place.direction === undefined) return request.method === "PUT" ? "claim" : "erase";
  if (place.tail === "watch") return "watch";
  if (place.tail !== undefined) return "put";
  return { GET: "fetch", HEAD: "last", DELETE: "prune" }[request.method] ?? "other";
}

/**
 * One data point per request past the gate: app, operation, status class,
 * request count and bytes received. No mailbox, token, sequence or IP address.
 * Only relay.zerobyte.cloud binds `USAGE`; a self-hosted relay counts nothing.
 */
function count(env, place, request, status) {
  if (!env.USAGE) return;
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  const bytes = Number.isFinite(declared) && declared > 0 ? declared : 0;
  try {
    env.USAGE.writeDataPoint({
      indexes: [place.app],
      blobs: [place.app, operation(request, place), `${Math.floor(status / 100)}xx`],
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
  if (request.method === "OPTIONS") {
    return reply(204, null, {
      "Access-Control-Allow-Methods": "GET, HEAD, PUT, DELETE",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
    });
  }
  if (!bearer(request)) return reply(401);
  // One object per app and mailbox: two apps never share a mailbox.
  const stub = env.MAILBOX.get(env.MAILBOX.idFromName(`${place.app}/${place.mailbox}`));
  const response = await stub.fetch(request);
  count(env, place, request, response.status);
  return response;
}

/**
 * One mailbox. State, under `ctx.storage`:
 *   meta        { digest, last: { p2c, c2p } (decimal strings), bytes }
 *   e:<dir>:<seq, 20 digits>   Uint8Array envelope
 *
 * `ctx` provides `storage` (get, put, list, delete, deleteAll, setAlarm,
 * deleteAlarm), `sockets(tag?)` and `upgrade(request, tag, protocol)`.
 *
 * Everything that is not a storage call (reading the body, hashing the token)
 * happens before `meta` is read, so no other request can change the mailbox
 * between reading `meta` and writing it back.
 */
export class Mailbox {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async meta() {
    return (await this.ctx.storage.get("meta")) ?? null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const { direction: directionName, tail } = route(url.pathname, this.env.APPS);

    let body = null;
    if (request.method === "PUT") {
      const declared = Number(request.headers.get("Content-Length") ?? "0");
      if (declared > LIMITS.envelopeBytes) return reply(413);
      body = new Uint8Array(await request.arrayBuffer());
      if (body.length > LIMITS.envelopeBytes) return reply(413);
    }
    const tokenDigest = await digest(bearer(request));
    const meta = await this.meta();

    if (directionName === undefined) {
      if (request.method === "PUT") return this.claim(body, meta, tokenDigest);
      if (!meta || !sameText(meta.digest, tokenDigest)) return reply(401);
      if (request.method === "DELETE") return this.erase();
      return reply(405, null, { Allow: "PUT, DELETE" });
    }

    if (!meta || !sameText(meta.digest, tokenDigest)) return reply(401);
    const direction = DIRECTIONS[directionName];
    if (!direction) return reply(404);

    if (tail === "watch") return this.watch(request, directionName);
    if (tail !== undefined) {
      if (request.method !== "PUT") return reply(405, null, { Allow: "PUT" });
      const sequence = parseSequence(tail);
      if (sequence === null) return reply(404);
      return this.put(body, meta, directionName, direction, sequence);
    }
    switch (request.method) {
      case "GET":
        return this.list(url, meta, directionName);
      case "HEAD":
        return reply(200, null, this.lastHeader(meta, directionName));
      case "DELETE":
        return this.prune(url, meta, directionName);
      default:
        return reply(405, null, { Allow: "GET, HEAD, DELETE" });
    }
  }

  lastHeader(meta, directionName) {
    const last = meta.last[directionName];
    return last ? { "X-Relay-Last": last } : {};
  }

  async claim(body, meta, tokenDigest) {
    if (meta) return sameText(meta.digest, tokenDigest) ? reply(204) : reply(403);
    // A claim names the digest of its own token, so a mistyped client never
    // locks a mailbox it cannot open again.
    let claimed = null;
    try {
      claimed = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return reply(400);
    }
    if (!sameText(claimed?.tokenDigest, tokenDigest)) return reply(400);
    await this.ctx.storage.put("meta", { digest: tokenDigest, last: {}, bytes: 0 });
    await this.touch();
    return reply(201);
  }

  async put(bytes, meta, directionName, direction, sequence) {
    const header = envelopeHeader(bytes);
    if (!header || header.version !== 1 || header.direction !== direction) return reply(400);
    if (header.sequence !== sequence) return reply(400);
    const last = BigInt(meta.last[directionName] ?? "0");
    if (sequence <= last) return reply(409, null, this.lastHeader(meta, directionName));

    const stored = await this.ctx.storage.list({ prefix: `e:${directionName}:` });
    if (stored.size >= LIMITS.envelopesPerDirection) return reply(507);
    if (meta.bytes + bytes.length > LIMITS.mailboxBytes) return reply(507);

    meta.last[directionName] = sequence.toString();
    meta.bytes += bytes.length;
    await this.ctx.storage.put({ [`e:${directionName}:${pad(sequence)}`]: bytes, meta });
    await this.touch();
    for (const socket of this.ctx.sockets(directionName)) {
      try {
        socket.send(sequence.toString());
      } catch {
        // A closed watcher fetches on its next connection.
      }
    }
    return reply(201);
  }

  async list(url, meta, directionName) {
    const after = url.searchParams.get("after") ?? "0";
    const from = after === "0" ? 0n : parseSequence(after);
    if (from === null) return reply(400);
    const asked = Number(url.searchParams.get("limit") ?? LIMITS.fetchLimit);
    const limit = Number.isInteger(asked) && asked > 0 ? Math.min(asked, LIMITS.fetchLimit) : 0;
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
    const stored = await this.ctx.storage.list({ prefix, end: prefix + pad(through + 1n) });
    if (stored.size > 0) {
      for (const value of stored.values()) meta.bytes -= value.byteLength ?? value.length;
      meta.bytes = Math.max(0, meta.bytes);
      await this.ctx.storage.delete([...stored.keys()]);
      await this.ctx.storage.put("meta", meta);
    }
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

  watch(request, directionName) {
    if ((request.headers.get("Upgrade") ?? "").toLowerCase() !== "websocket") return reply(426);
    const offered = offeredProtocols(request);
    // Answer with the protocol name, never with the bearer subprotocol.
    const protocol = offered.includes(WATCH_PROTOCOL) ? WATCH_PROTOCOL : null;
    return this.ctx.upgrade(request, directionName, protocol);
  }

  webSocketMessage(socket) {
    // Watchers only listen.
    socket.close(1003, "listen only");
  }

  webSocketClose(socket, code) {
    try {
      socket.close(code, "closed");
    } catch {
      // Already closed.
    }
  }

  async touch() {
    await this.ctx.storage.setAlarm(Date.now() + LIMITS.idleMilliseconds);
  }

  async alarm() {
    await this.erase();
  }
}
