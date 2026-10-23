import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeEach, test } from "node:test";

import worker, { Mailbox } from "../src/cloudflare.js";
import { LIMITS, envelopeHeader, joinEnvelopes, route } from "../src/core.js";

// An in-memory stand-in for Durable Object storage: sorted keys, `start`
// inclusive, `end` exclusive, `limit`, structured values — what the Worker uses.
class MemoryStorage {
  constructor() {
    this.map = new Map();
    this.alarm = null;
  }
  async get(key) {
    return structuredClone(this.map.get(key));
  }
  async put(keyOrEntries, value) {
    const entries = typeof keyOrEntries === "string" ? { [keyOrEntries]: value } : keyOrEntries;
    for (const [k, v] of Object.entries(entries)) this.map.set(k, structuredClone(v));
  }
  async list({ prefix = "", start, end, limit } = {}) {
    const keys = [...this.map.keys()]
      .filter((k) => k.startsWith(prefix))
      .filter((k) => (start === undefined || k >= start) && (end === undefined || k < end))
      .sort();
    return new Map(keys.slice(0, limit ?? keys.length).map((k) => [k, this.map.get(k)]));
  }
  async delete(keys) {
    for (const k of keys) this.map.delete(k);
  }
  async deleteAll() {
    this.map.clear();
  }
  async setAlarm(at) {
    this.alarm = at;
  }
  async deleteAlarm() {
    this.alarm = null;
  }
}

const APPS = Object.freeze({ "01a1601b-fa85-7d58-b2a2-1416e0a6b054": { name: "derived" } });

let objects;
let env;
let usage;
beforeEach(() => {
  objects = new Map();
  usage = [];
  env = {
    APPS,
    USAGE: { writeDataPoint: (point) => usage.push(point) },
    MAILBOX: {
      idFromName: (name) => name,
      get: (id) => {
        if (!objects.has(id)) {
          const storage = new MemoryStorage();
          objects.set(id, new Mailbox({ storage, getWebSockets: () => [] }, env));
        }
        return objects.get(id);
      },
    },
  };
});

const vectors = JSON.parse(readFileSync(new URL("../vectors/relay-v1.json", import.meta.url)));

const APP = "01a1601b-fa85-7d58-b2a2-1416e0a6b054";
const MAILBOX = "41fa13c183c0c2092a085390c172cba1";
const TOKEN = "16Lm3t_PFz5tqDn_w8cIkbkUtj8zrxVcMgO4_qSNX74";
const OTHER = "A".repeat(43);
const BASE = `https://relay.zerobyte.cloud/v1/${APP}/mailbox/${MAILBOX}`;
const digest = (t) => createHash("sha256").update(Buffer.from(t, "base64url")).digest("hex");

function call(path, { method = "GET", token = TOKEN, body, headers = {} } = {}) {
  return worker.fetch(
    new Request(BASE + path, {
      method,
      body,
      headers: { Authorization: `Bearer ${token}`, ...headers },
    }),
    env,
  );
}

function envelope(direction, sequence, size = 64) {
  const bytes = new Uint8Array(size);
  bytes[0] = 1;
  bytes[1] = direction;
  new DataView(bytes.buffer).setBigUint64(2, BigInt(sequence));
  bytes.fill(0xab, 10);
  return bytes;
}

function split(buffer) {
  const view = new DataView(buffer);
  const count = view.getUint32(0);
  const out = [];
  let offset = 4;
  for (let i = 0; i < count; i += 1) {
    const length = view.getUint32(offset);
    out.push(new Uint8Array(buffer.slice(offset + 4, offset + 4 + length)));
    offset += 4 + length;
  }
  assert.equal(offset, buffer.byteLength);
  return out;
}

async function claim(token = TOKEN) {
  return call("", { method: "PUT", token, body: JSON.stringify({ tokenDigest: digest(token) }) });
}

test("The bearer digest matches the protocol vectors", () => {
  for (const set of vectors.credentials) assert.equal(digest(set.bearer), set.tokenDigest);
  assert.equal(TOKEN, vectors.credentials[0].bearer);
  assert.equal(MAILBOX, vectors.credentials[0].mailbox);
});

test("The relay reads the clear header of every vector envelope", () => {
  for (const e of vectors.envelopes) {
    const header = envelopeHeader(Buffer.from(e.envelope, "hex"));
    assert.equal(header.version, 1);
    assert.equal(header.direction, e.direction);
    assert.equal(header.sequence, BigInt(e.sequence));
  }
});

test("Unknown paths, malformed mailboxes and missing tokens are refused before storage", async () => {
  assert.equal((await worker.fetch(new Request("https://relay.zerobyte.cloud/"), env)).status, 404);
  const bad = await worker.fetch(
    new Request(`https://relay.zerobyte.cloud/v1/${APP}/mailbox/XYZ`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    }),
    env,
  );
  assert.equal(bad.status, 404);
  assert.equal((await call("", { method: "PUT", token: "short" })).status, 401);
  assert.equal(objects.size, 0);
});

test("The first claim wins; a second token is refused and cannot read", async () => {
  assert.equal((await claim()).status, 201);
  assert.equal((await claim()).status, 204);
  assert.equal((await claim(OTHER)).status, 403);
  assert.equal((await call("/p2c", { token: OTHER })).status, 401);
});

test("A claim whose digest does not match its own token is refused", async () => {
  const response = await call("", {
    method: "PUT",
    body: JSON.stringify({ tokenDigest: digest(OTHER) }),
  });
  assert.equal(response.status, 400);
  assert.equal((await claim()).status, 201);
});

test("An unclaimed mailbox accepts nothing", async () => {
  const response = await call("/p2c/1", { method: "PUT", body: envelope(1, 1) });
  assert.equal(response.status, 401);
});

test("Envelopes are stored in sequence and paged back", async () => {
  await claim();
  for (let s = 1; s <= 20; s += 1) {
    const r = await call(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) });
    assert.equal(r.status, 201);
  }
  const first = await call("/p2c?after=0&limit=16");
  assert.equal(first.headers.get("X-Relay-More"), "1");
  assert.equal(first.headers.get("X-Relay-Last"), "20");
  const page = split(await first.arrayBuffer());
  assert.equal(page.length, 16);
  assert.deepEqual(
    page.map((e) => Number(envelopeHeader(e).sequence)),
    Array.from({ length: 16 }, (_, i) => i + 1),
  );
  const rest = split(await (await call("/p2c?after=16")).arrayBuffer());
  assert.deepEqual(rest.map((e) => Number(envelopeHeader(e).sequence)), [17, 18, 19, 20]);
  const head = await call("/p2c", { method: "HEAD" });
  assert.equal(head.headers.get("X-Relay-Last"), "20");
});

test("Sequences only grow, and the header must agree with the path", async () => {
  await claim();
  assert.equal((await call("/p2c/5", { method: "PUT", body: envelope(1, 5) })).status, 201);
  assert.equal((await call("/p2c/5", { method: "PUT", body: envelope(1, 5) })).status, 409);
  assert.equal((await call("/p2c/4", { method: "PUT", body: envelope(1, 4) })).status, 409);
  assert.equal((await call("/p2c/6", { method: "PUT", body: envelope(1, 7) })).status, 400);
  assert.equal((await call("/p2c/6", { method: "PUT", body: envelope(2, 6) })).status, 400);
  const future = envelope(1, 6);
  future[0] = 2;
  assert.equal((await call("/p2c/6", { method: "PUT", body: future })).status, 400);
  assert.equal((await call("/p2c/6", { method: "PUT", body: envelope(1, 6, 20) })).status, 400);
  // Each direction counts on its own.
  assert.equal((await call("/c2p/1", { method: "PUT", body: envelope(2, 1) })).status, 201);
});

test("An oversized envelope and a full mailbox are refused", async () => {
  await claim();
  const big = envelope(1, 1, LIMITS.envelopeBytes + 1);
  assert.equal((await call("/p2c/1", { method: "PUT", body: big })).status, 413);
  for (let s = 1; s <= LIMITS.envelopesPerDirection; s += 1) {
    await call(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) });
  }
  const over = LIMITS.envelopesPerDirection + 1;
  assert.equal((await call(`/p2c/${over}`, { method: "PUT", body: envelope(1, over) })).status, 507);
  // Reading and pruning makes room again.
  assert.equal((await call(`/p2c?through=${over - 1}`, { method: "DELETE" })).status, 204);
  assert.equal((await call(`/p2c/${over}`, { method: "PUT", body: envelope(1, over) })).status, 201);
});

test("The byte quota counts what is stored, and pruning gives it back", async () => {
  await claim();
  const size = 1_000_000;
  const fits = Math.floor(LIMITS.mailboxBytes / size);
  for (let s = 1; s <= fits; s += 1) {
    assert.equal((await call(`/p2c/${s}`, { method: "PUT", body: envelope(1, s, size) })).status, 201);
  }
  const next = fits + 1;
  assert.equal((await call(`/p2c/${next}`, { method: "PUT", body: envelope(1, next, size) })).status, 507);
  await call(`/p2c?through=${fits}`, { method: "DELETE" });
  assert.equal((await call(`/p2c/${next}`, { method: "PUT", body: envelope(1, next, size) })).status, 201);
});

test("Pruning drops only what the reader has read, and keeps the sequence", async () => {
  await claim();
  for (let s = 1; s <= 4; s += 1) await call(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) });
  await call("/p2c?through=2", { method: "DELETE" });
  const left = split(await (await call("/p2c?after=0")).arrayBuffer());
  assert.deepEqual(left.map((e) => Number(envelopeHeader(e).sequence)), [3, 4]);
  assert.equal((await call("/p2c/2", { method: "PUT", body: envelope(1, 2) })).status, 409);
});

test("Erasing removes everything, including the claim, and idle mailboxes erase themselves", async () => {
  await claim();
  await call("/p2c/1", { method: "PUT", body: envelope(1, 1) });
  const box = objects.get(`${APP}/${MAILBOX}`);
  assert.ok(box.ctx.storage.alarm > Date.now() + LIMITS.idleMilliseconds - 60_000);
  assert.equal((await call("", { method: "DELETE" })).status, 204);
  assert.equal(box.ctx.storage.map.size, 0);
  assert.equal((await call("/p2c")).status, 401);

  await claim(OTHER);
  await box.alarm();
  assert.equal(box.ctx.storage.map.size, 0);
});

test("Responses are never cached", async () => {
  await claim();
  const response = await call("/p2c?after=0");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.deepEqual(split(await response.arrayBuffer()), []);
});

test("The fetch body matches the protocol vectors", () => {
  const joined = joinEnvelopes([new Uint8Array([1, 2]), new Uint8Array([3])]);
  assert.deepEqual([...joined], [0, 0, 0, 2, 0, 0, 0, 2, 1, 2, 0, 0, 0, 1, 3]);
  for (const w of vectors.wire) {
    const body = joinEnvelopes(w.envelopes.map((e) => Buffer.from(e, "hex")));
    assert.equal(Buffer.from(body).toString("hex"), w.body);
  }
});

test("The bare host, a missing or unknown app and the old path all answer the same JSON 404", async () => {
  const unknown = "01a1601b-fa85-7d58-b2a2-1416e0a6b055";
  const paths = [
    "/",
    "/v1",
    "/v1/",
    `/v1/${APP}`,
    `/v1/${APP}/mailbox`,
    `/v1/mailbox/${MAILBOX}`,
    `/v1/${unknown}/mailbox/${MAILBOX}`,
    `/v1/${APP.slice(0, 8)}/mailbox/${MAILBOX}`,
    `/v1/${APP.toUpperCase()}/mailbox/${MAILBOX}`,
    `/v1/${APP}/box/${MAILBOX}`,
    `/v2/${APP}/mailbox/${MAILBOX}`,
    `/v1/${APP}/mailbox/${MAILBOX}/p2c/1/extra`,
  ];
  for (const path of paths) {
    const response = await worker.fetch(
      new Request("https://relay.zerobyte.cloud" + path, {
        method: "PUT",
        headers: { Authorization: `Bearer ${TOKEN}` },
      }),
      env,
    );
    assert.equal(response.status, 404, path);
    assert.equal(response.headers.get("Content-Type"), "application/json; charset=utf-8", path);
    assert.deepEqual(await response.json(), { error: "not_found", status: 404 }, path);
  }
  assert.equal(objects.size, 0);
  assert.equal(usage.length, 0);
});

test("Two apps with the same mailbox name get separate mailboxes", async () => {
  const other = "01a1601c-0000-7000-8000-000000000001";
  const apps = { [APP]: {}, [other]: {} };
  env.APPS = apps;
  assert.equal((await claim()).status, 201);
  const theirs = await worker.fetch(
    new Request(`https://relay.zerobyte.cloud/v1/${other}/mailbox/${MAILBOX}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${OTHER}` },
      body: JSON.stringify({ tokenDigest: digest(OTHER) }),
    }),
    env,
  );
  assert.equal(theirs.status, 201);
  assert.equal(objects.size, 2);
  assert.deepEqual(route(`/v1/${other}/mailbox/${MAILBOX}/c2p`, apps), {
    app: other,
    mailbox: MAILBOX,
    direction: "c2p",
    tail: undefined,
  });
});

test("Usage counts carry the app, operation, status class and bytes, never the mailbox", async () => {
  await claim();
  const bytes = envelope(1, 1, 100);
  // URLSession sends Content-Length for a Data body; the count takes it from there.
  await call("/p2c/1", { method: "PUT", body: bytes, headers: { "Content-Length": "100" } });
  await call("/p2c?after=0&limit=4");
  assert.deepEqual(
    usage.map((p) => p.blobs),
    [
      [APP, "claim", "2xx"],
      [APP, "put", "2xx"],
      [APP, "fetch", "2xx"],
    ],
  );
  assert.deepEqual(usage[1].doubles, [1, 100]);
  for (const point of usage) {
    const text = JSON.stringify(point);
    assert.ok(!text.includes(MAILBOX) && !text.includes(TOKEN), text);
  }
});

test("Errors are JSON with a stable code; envelopes stay binary", async () => {
  const anonymous = await worker.fetch(new Request(BASE), env);
  assert.equal(anonymous.status, 401);
  assert.deepEqual(await anonymous.json(), { error: "unauthorized", status: 401 });
  await claim();
  const conflict = await call("/p2c/1", { method: "PUT", body: envelope(2, 1, 10) });
  assert.equal(conflict.status, 400);
  assert.deepEqual(await conflict.json(), { error: "bad_request", status: 400 });
  const page = await call("/p2c?after=0&limit=4");
  assert.equal(page.headers.get("Content-Type"), "application/octet-stream");
});
