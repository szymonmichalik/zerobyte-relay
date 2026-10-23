// The self-hosted relay over real HTTP and a real WebSocket, on SQLite.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import { appsFrom, newAppID } from "../src/apps.js";
import { LIMITS } from "../src/core.js";
import { createRelay, createRelayServer } from "../src/node/server.js";

const APP = "01a1601b-fa85-7d58-b2a2-1416e0a6b054";
let server;
let base;
let directory;

before(async () => {
  directory = mkdtempSync(join(tmpdir(), "zerobyte-relay-"));
  server = createRelayServer({ apps: `${APP}=derived`, database: join(directory, "relay.sqlite") });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(directory, { recursive: true, force: true });
});

function link() {
  const token = randomBytes(32);
  return {
    mailbox: randomBytes(16).toString("hex"),
    bearer: token.toString("base64url"),
    digest: createHash("sha256").update(token).digest("hex"),
  };
}

function envelope(direction, sequence, size = 64) {
  const bytes = new Uint8Array(size);
  bytes[0] = 1;
  bytes[1] = direction;
  new DataView(bytes.buffer).setBigUint64(2, BigInt(sequence));
  bytes.fill(0xcd, 10);
  return bytes;
}

function call(l, path, { method = "GET", body, headers = {} } = {}) {
  return fetch(`${base}/v1/${APP}/mailbox/${l.mailbox}${path}`, {
    method,
    body,
    headers: { Authorization: `Bearer ${l.bearer}`, ...headers },
  });
}

const claim = (l) =>
  call(l, "", { method: "PUT", body: JSON.stringify({ tokenDigest: l.digest }) });

test("A claim, a write, a page and a prune work over HTTP and survive in SQLite", async () => {
  const l = link();
  assert.equal((await claim(l)).status, 201);
  for (let s = 1; s <= 3; s += 1) {
    assert.equal((await call(l, `/p2c/${s}`, { method: "PUT", body: envelope(1, s) })).status, 201);
  }
  const page = await call(l, "/p2c?after=1&limit=16");
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("x-relay-last"), "3");
  assert.equal(page.headers.get("x-relay-more"), "0");
  const body = new Uint8Array(await page.arrayBuffer());
  assert.equal(new DataView(body.buffer).getUint32(0), 2);
  assert.equal(body.length, 4 + 2 * (4 + 64));
  assert.equal((await call(l, "/p2c?through=3", { method: "DELETE" })).status, 204);
  const empty = new Uint8Array(await (await call(l, "/p2c")).arrayBuffer());
  assert.deepEqual([...empty], [0, 0, 0, 0]);
  const head = await call(l, "/p2c", { method: "HEAD" });
  assert.equal(head.headers.get("x-relay-last"), "3");
  assert.equal((await call(l, "/p2c/3", { method: "PUT", body: envelope(1, 3) })).status, 409);
});

test("Envelopes are returned byte for byte", async () => {
  const l = link();
  await claim(l);
  const sent = envelope(2, 9, 5000);
  crypto.getRandomValues(sent.subarray(10));
  await call(l, "/c2p/9", { method: "PUT", body: sent });
  const body = new Uint8Array(await (await call(l, "/c2p")).arrayBuffer());
  assert.deepEqual(body.subarray(8), sent);
});

test("A body over the limit is refused with 413 without being stored", async () => {
  const l = link();
  await claim(l);
  const big = envelope(1, 1, LIMITS.envelopeBytes + 1);
  const response = await call(l, "/p2c/1", { method: "PUT", body: big });
  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: "envelope_too_large", status: 413 });
  assert.equal((await call(l, "/p2c", { method: "HEAD" })).headers.get("x-relay-last"), null);
});

test("Concurrent writes to one mailbox are serialised: one wins per sequence", async () => {
  const l = link();
  await claim(l);
  const results = await Promise.all(
    Array.from({ length: 8 }, () => call(l, "/p2c/1", { method: "PUT", body: envelope(1, 1) })),
  );
  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [201, 409, 409, 409, 409, 409, 409, 409]);
});

test("Unknown apps and paths answer the same JSON 404; CORS preflight is answered", async () => {
  for (const path of ["/", `/v1/${APP}`, `/v1/${newAppID()}/mailbox/${"0".repeat(32)}`]) {
    const response = await fetch(base + path);
    assert.equal(response.status, 404, path);
    assert.deepEqual(await response.json(), { error: "not_found", status: 404 });
  }
  const preflight = await fetch(`${base}/v1/${APP}/mailbox/${"0".repeat(32)}/p2c`, {
    method: "OPTIONS",
  });
  assert.equal(preflight.status, 204);
  assert.match(preflight.headers.get("access-control-allow-headers"), /Authorization/);
  assert.equal(preflight.headers.get("access-control-allow-origin"), "*");
});

// A minimal masked WebSocket client, enough to watch.
function openWatch(l, direction, { protocols, header = true } = {}) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const headers = {
      Connection: "Upgrade",
      Upgrade: "websocket",
      "Sec-WebSocket-Key": key,
      "Sec-WebSocket-Version": "13",
    };
    if (header) headers.Authorization = `Bearer ${l.bearer}`;
    if (protocols) headers["Sec-WebSocket-Protocol"] = protocols.join(", ");
    const req = httpRequest(`${base}/v1/${APP}/mailbox/${l.mailbox}/${direction}/watch`, {
      headers,
    });
    req.on("upgrade", (response, socket) => {
      const messages = [];
      let waiting = null;
      let buffer = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 2) {
          const length = buffer[1] & 0x7f;
          if (buffer.length < 2 + length) break;
          const opcode = buffer[0] & 0x0f;
          const payload = buffer.subarray(2, 2 + length).toString();
          buffer = buffer.subarray(2 + length);
          if (opcode === 0x1) {
            messages.push(payload);
            waiting?.();
          }
          if (opcode === 0x8) messages.push("close");
        }
      });
      resolve({
        protocol: response.headers["sec-websocket-protocol"],
        messages,
        next: () =>
          new Promise((done) => {
            if (messages.length) return done(messages.shift());
            waiting = () => {
              waiting = null;
              done(messages.shift());
            };
          }),
        close: () => socket.destroy(),
      });
    });
    req.on("response", (response) => resolve({ status: response.statusCode }));
    req.on("error", reject);
    req.end();
  });
}

test("A watcher hears the sequence number of each write in its direction only", async () => {
  const l = link();
  await claim(l);
  const watch = await openWatch(l, "p2c", { protocols: ["zerobyte.v1"] });
  assert.equal(watch.protocol, "zerobyte.v1");
  await call(l, "/c2p/1", { method: "PUT", body: envelope(2, 1) });
  await call(l, "/p2c/7", { method: "PUT", body: envelope(1, 7) });
  assert.equal(await watch.next(), "7");
  assert.equal(watch.messages.length, 0);
  watch.close();
});

test("A browser watcher can authorise with the bearer subprotocol, which is never echoed", async () => {
  const l = link();
  await claim(l);
  const watch = await openWatch(l, "c2p", {
    header: false,
    protocols: ["zerobyte.v1", `zerobyte.bearer.${l.bearer}`],
  });
  assert.equal(watch.protocol, "zerobyte.v1");
  await call(l, "/c2p/2", { method: "PUT", body: envelope(2, 2) });
  assert.equal(await watch.next(), "2");
  watch.close();

  const stranger = await openWatch(link(), "c2p", { protocols: ["zerobyte.v1"] });
  assert.equal(stranger.status, 401);
});

test("An idle mailbox is erased by the sweep", async () => {
  let clock = 1_000_000;
  const relay = createRelay({ apps: appsFrom(APP), now: () => clock });
  const l = link();
  const at = (path, init = {}) =>
    relay.fetch(
      new Request(`http://r/v1/${APP}/mailbox/${l.mailbox}${path}`, {
        ...init,
        headers: { Authorization: `Bearer ${l.bearer}` },
      }),
    );
  assert.equal(
    (await at("", { method: "PUT", body: JSON.stringify({ tokenDigest: l.digest }) })).status,
    201,
  );
  await at("/p2c/1", { method: "PUT", body: envelope(1, 1) });
  clock = Date.now() + LIMITS.idleMilliseconds + 1;
  await relay.sweep();
  assert.equal((await at("/p2c")).status, 401);
  relay.close();
});

test("App ids are whole lowercase UUIDv7s", () => {
  for (let i = 0; i < 100; i += 1) assert.doesNotThrow(() => appsFrom(newAppID()));
  assert.equal(newAppID(0x01a1601bfa85, new Uint8Array(10)), "01a1601b-fa85-7000-8000-000000000000");
  assert.throws(() => appsFrom(APP.toUpperCase()));
  assert.throws(() => appsFrom("6f1c2a3b-4d5e-4f60-8172-93a4b5c6d7e8"));
  assert.deepEqual(Object.keys(appsFrom(` ${APP}=derived ,\n`)), [APP]);
});
