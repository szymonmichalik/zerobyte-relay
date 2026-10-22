// The optional extensions: app profiles, rate limits, push, signal and ICE.
// Push and TURN providers are stand-ins; nothing leaves the machine.

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import { appsFrom } from "../src/apps.js";
import { DEFAULT_LIMITS } from "../src/core.js";
import { iceFrom, iceServers } from "../src/ice.js";
import { apnsFrom } from "../src/apns/index.js";
import { parseRegistration, pushProviders, PUSH } from "../src/push.js";
import { RATES, take } from "../src/rate.js";
import { createRelay, createRelayServer } from "../src/node/server.js";

const PLAIN = "01a1601b-fa85-7d58-b2a2-1416e0a6b054";
const CHAT = "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8";
const SMALL = "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e9";
const RELAY_APPS = [
  `${PLAIN}=derived`,
  `${CHAT}=chat;push=com.example.chat;signal;ice;envelopes=1024;idle=90`,
  `${SMALL}=small;envelopes=16;mailbox=1;envelope=64`,
].join(",");

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" });
const DEVICE = "ab".repeat(32);

function fakeApns(answer = () => ({ status: 200, body: "" })) {
  const sent = [];
  const deliver = async (request) => {
    sent.push(request);
    return answer(request);
  };
  const apns = apnsFrom(
    { APNS_TEAM_ID: "TEAM123456", APNS_KEY_ID: "KEY1234567", APNS_PRIVATE_KEY: PEM },
    deliver,
  );
  return { apns, push: pushProviders(apns), sent };
}

function fakeIce(answer) {
  const calls = [];
  const ice = iceFrom(
    {
      ICE_STUN_URLS: "stun:stun.example.com:3478",
      TURN_URLS: "turn:turn.example.com:3478?transport=udp,turns:turn.example.com:5349",
      TURN_SECRET: "coturn-secret",
      CF_TURN_KEY_ID: "key-id",
      CF_TURN_API_TOKEN: "api-token",
    },
    async (url, init) => {
      calls.push({ url, init });
      return answer();
    },
  );
  return { ice, calls };
}

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

function client(relay, app, l = link()) {
  const at = (path, { method = "GET", body, headers = {} } = {}) =>
    relay.fetch(
      new Request(`http://relay.invalid/v1/${app}/mailbox/${l.mailbox}${path}`, {
        method,
        body,
        headers: { Authorization: `Bearer ${l.bearer}`, ...headers },
      }),
    );
  at.link = l;
  at.claim = () => at("", { method: "PUT", body: JSON.stringify({ tokenDigest: l.digest }) });
  return at;
}

const registration = (extra = {}) =>
  JSON.stringify({ service: "apns", token: DEVICE, environment: "production", tag: "chat-7", ...extra });

// ---- profiles --------------------------------------------------------------

test("An app id alone keeps the Relay Protocol v1 defaults", () => {
  const apps = appsFrom(RELAY_APPS);
  assert.equal(apps[PLAIN].name, "derived");
  assert.deepEqual(apps[PLAIN].limits, DEFAULT_LIMITS);
  assert.deepEqual(apps[PLAIN].features, { push: null, signal: false, ice: false });
});

test("Options set limits and features per app", () => {
  const apps = appsFrom(RELAY_APPS);
  assert.equal(apps[CHAT].features.push, "com.example.chat");
  assert.equal(apps[CHAT].features.signal, true);
  assert.equal(apps[CHAT].limits.envelopesPerDirection, 1024);
  assert.equal(apps[CHAT].limits.idleMilliseconds, 90 * 86_400_000);
  assert.equal(apps[SMALL].limits.mailboxBytes, 1_048_576);
  assert.equal(apps[SMALL].limits.envelopeBytes, 64 * 1024 + 38);
});

test("A bad option stops the relay at start-up", () => {
  for (const bad of [
    `${CHAT};push`,
    `${CHAT};push=has space`,
    `${CHAT};envelopes=8`,
    `${CHAT};envelopes=5000`,
    `${CHAT};mailbox=0`,
    `${CHAT};idle=1.5`,
    `${CHAT};signal=yes`,
    `${CHAT};fast`,
    `${CHAT};ice;ice`,
    `${CHAT};mailbox=1;envelope=1024`,
    `${CHAT},${CHAT}`,
  ]) {
    assert.throws(() => appsFrom(bad), /RELAY_APPS/, bad);
  }
});

test("Per-app quotas: a small app fills at 16 envelopes and refuses large ones", async () => {
  const relay = createRelay({ apps: RELAY_APPS });
  const at = client(relay, SMALL);
  await at.claim();
  for (let s = 1; s <= 16; s += 1) {
    assert.equal((await at(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) })).status, 201);
  }
  assert.equal((await at("/p2c/17", { method: "PUT", body: envelope(1, 17) })).status, 507);
  await at("/p2c?through=16", { method: "DELETE" });
  assert.equal((await at("/p2c/17", { method: "PUT", body: envelope(1, 17) })).status, 201);
  const big = envelope(1, 18, 64 * 1024 + 39);
  assert.equal((await at("/p2c/18", { method: "PUT", body: big })).status, 413);
  relay.close();
});

test("A large quota is counted, not listed, on every write", async () => {
  const relay = createRelay({ apps: RELAY_APPS });
  const at = client(relay, CHAT);
  await at.claim();
  for (let s = 1; s <= 100; s += 1) {
    assert.equal((await at(`/c2p/${s}`, { method: "PUT", body: envelope(2, s) })).status, 201);
  }
  const meta = await relay.database.storage(`${CHAT}/${at.link.mailbox}`).get("meta");
  assert.deepEqual(meta.count, { p2c: 0, c2p: 100 });
  await at("/c2p?through=40", { method: "DELETE" });
  const after = await relay.database.storage(`${CHAT}/${at.link.mailbox}`).get("meta");
  assert.equal(after.count.c2p, 60);
  assert.equal(after.bytes, 60 * 64);
  relay.close();
});

test("A mailbox stored before the counter existed is counted once and then kept", async () => {
  const relay = createRelay({ apps: RELAY_APPS });
  const at = client(relay, SMALL);
  await at.claim();
  for (let s = 1; s <= 3; s += 1) await at(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) });
  const storage = relay.database.storage(`${SMALL}/${at.link.mailbox}`);
  const meta = await storage.get("meta");
  delete meta.count;
  await storage.put("meta", meta);
  assert.equal((await at("/p2c/4", { method: "PUT", body: envelope(1, 4) })).status, 201);
  assert.deepEqual((await storage.get("meta")).count, { p2c: 4 });
  relay.close();
});

test("A confirmed claim restarts the idle timer, so it works as a heartbeat", async () => {
  let clock = 1_000_000;
  const relay = createRelay({ apps: RELAY_APPS, now: () => clock });
  const at = client(relay, PLAIN);
  await at.claim();
  const storage = relay.database.storage(`${PLAIN}/${at.link.mailbox}`);
  const first = await storage.getAlarm();
  clock += 5 * 86_400_000;
  assert.equal((await at.claim()).status, 204);
  assert.equal(await storage.getAlarm(), first + 5 * 86_400_000);
  relay.close();
});

test("Extensions an app did not enable do not exist", async () => {
  const relay = createRelay({ apps: RELAY_APPS, push: fakeApns().push, ice: fakeIce().ice });
  const at = client(relay, PLAIN);
  await at.claim();
  assert.equal((await at("/p2c/push", { method: "PUT", body: registration() })).status, 404);
  assert.equal((await at("/ice")).status, 404);
  assert.equal((await at("/signal/primary")).status, 404);
  const chat = client(relay, CHAT);
  await chat.claim();
  assert.equal((await chat("/signal/third")).status, 404);
  assert.equal((await chat("/ice/x")).status, 404);
  relay.close();
});

// ---- rate limits -----------------------------------------------------------

test("A bucket refills at its rate and answers how long to wait", () => {
  const memory = {};
  const rates = { write: { burst: 2, perSecond: 0.5 } };
  assert.equal(take(memory, "write", 0, rates), 0);
  assert.equal(take(memory, "write", 0, rates), 0);
  assert.equal(take(memory, "write", 0, rates), 2);
  assert.equal(take(memory, "write", 1000, rates), 1);
  assert.equal(take(memory, "write", 2000, rates), 0);
  assert.equal(take(memory, "write:x", 2000, rates), 0, "a suffix keeps a separate bucket");
});

test("A write loop gets 429 with Retry-After, and the mailbox recovers", async () => {
  let clock = 1_000_000;
  const relay = createRelay({ apps: RELAY_APPS, now: () => clock });
  const at = client(relay, CHAT);
  await at.claim();
  let s = 1;
  for (; s <= RATES.write.burst; s += 1) {
    assert.equal((await at(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) })).status, 201);
  }
  const refused = await at(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) });
  assert.equal(refused.status, 429);
  assert.equal(refused.headers.get("retry-after"), "1");
  assert.deepEqual(await refused.json(), { error: "rate_limited", status: 429 });
  clock += 1000;
  assert.equal((await at(`/p2c/${s}`, { method: "PUT", body: envelope(1, s) })).status, 201);
  relay.close();
});

// ---- push ------------------------------------------------------------------

test("Registrations are validated strictly", () => {
  const { push } = fakeApns();
  const parse = (text) => parseRegistration(new TextEncoder().encode(text), push);
  assert.deepEqual(parse(registration()), {
    service: "apns",
    token: DEVICE,
    environment: "production",
    tag: "chat-7",
  });
  assert.ok(parse(registration({ alert: "Nowa wiadomość" })));
  for (const bad of [
    registration({ service: "" }),
    registration({ service: "APNS" }),
    registration({ token: "AB".repeat(32) }),
    registration({ token: "ab".repeat(8) }),
    registration({ environment: "staging" }),
    registration({ tag: "" }),
    registration({ tag: "a/b" }),
    registration({ alert: "x".repeat(PUSH.alertCharacters + 1) }),
    registration({ extra: 1 }),
    "[]",
    "not json",
  ]) {
    assert.equal(parse(bad), null, bad);
  }
});

test("Push services are modules: core keeps a registration for one it does not know", () => {
  const { push } = fakeApns();
  const other = JSON.stringify({ service: "unifiedpush", endpoint: "https://up.example/x", tag: "t" });
  const bytes = new TextEncoder().encode(other);
  assert.deepEqual(parseRegistration(bytes, push), { service: "unifiedpush", endpoint: "https://up.example/x", tag: "t" });
  assert.ok(parseRegistration(new TextEncoder().encode(registration()), null), "APNs fields pass unchecked without the APNs module");
  const nested = JSON.stringify({ service: "x", endpoint: { a: 1 }, tag: "t" });
  assert.equal(parseRegistration(new TextEncoder().encode(nested), push), null, "unknown services get strings only");
  assert.throws(() => pushProviders(push.apns, push.apns), /two providers/);
  assert.equal(pushProviders(null), null);
});

test("The relay stores a registration sealed: no device token in its database", async () => {
  const { push } = fakeApns();
  const relay = createRelay({ apps: RELAY_APPS, push });
  const at = client(relay, CHAT);
  await at.claim();
  assert.equal((await at("/p2c/push", { method: "PUT", body: registration() })).status, 204);
  const rows = relay.database.db.prepare("SELECT key, value FROM entries").all();
  const dump = JSON.stringify(rows.map((r) => [r.key, Buffer.from(r.value).toString()]));
  assert.ok(dump.includes("push:p2c"));
  assert.ok(!dump.includes(DEVICE), "the device token is not stored in the clear");
  assert.ok(!dump.includes("chat-7"), "the tag is not stored in the clear");
  relay.close();
});

test("A write that asks for it wakes the reader with one content-free push", async () => {
  const { push, sent } = fakeApns();
  const relay = createRelay({ apps: RELAY_APPS, push });
  const at = client(relay, CHAT);
  await at.claim();
  await at("/p2c/push", { method: "PUT", body: registration({ alert: "Nowa wiadomość" }) });

  await at("/p2c/1", { method: "PUT", body: envelope(1, 1) });
  await relay.settled();
  assert.equal(sent.length, 0, "no push without X-Relay-Notify");

  const stored = await at("/p2c/2", {
    method: "PUT",
    body: envelope(1, 2),
    headers: { "X-Relay-Notify": "alert" },
  });
  assert.equal(stored.status, 201);
  await relay.settled();
  assert.equal(sent.length, 1);
  const [pushed] = sent;
  assert.equal(pushed.url, `https://api.push.apple.com/3/device/${DEVICE}`);
  assert.equal(pushed.headers["apns-topic"], "com.example.chat");
  assert.equal(pushed.headers["apns-push-type"], "alert");
  assert.equal(pushed.headers["apns-priority"], "10");
  const payload = JSON.parse(pushed.body);
  assert.deepEqual(payload, {
    aps: { alert: { body: "Nowa wiadomość" }, "mutable-content": 1, sound: "default" },
    zerobyte: { tag: "chat-7" },
  });
  assert.ok(!pushed.body.includes(at.link.mailbox), "the push does not name the mailbox");

  // The provider token is an ES256 JWT that verifies with the key's public half.
  const jwt = pushed.headers.authorization.replace(/^bearer /, "");
  const [h, c, s] = jwt.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url")), { alg: "ES256", kid: "KEY1234567" });
  assert.equal(JSON.parse(Buffer.from(c, "base64url")).iss, "TEAM123456");
  assert.ok(
    verify("sha256", Buffer.from(`${h}.${c}`), { key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url")),
  );

  await at("/p2c/3", { method: "PUT", body: envelope(1, 3), headers: { "X-Relay-Notify": "silent" } });
  await relay.settled();
  assert.equal(sent[1].headers["apns-push-type"], "background");
  assert.deepEqual(JSON.parse(sent[1].body), { aps: { "content-available": 1 }, zerobyte: { tag: "chat-7" } });
  assert.equal(sent[1].headers.authorization, pushed.headers.authorization, "the provider token is reused");
  relay.close();
});

test("Only the direction's own reader is woken, and an unknown notify value is refused", async () => {
  const { push, sent } = fakeApns();
  const relay = createRelay({ apps: RELAY_APPS, push });
  const at = client(relay, CHAT);
  await at.claim();
  await at("/c2p/push", { method: "PUT", body: registration({ environment: "development" }) });
  await at("/p2c/1", { method: "PUT", body: envelope(1, 1), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  assert.equal(sent.length, 0);
  await at("/c2p/1", { method: "PUT", body: envelope(2, 1), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  assert.equal(sent.length, 1);
  assert.match(sent[0].url, /^https:\/\/api\.sandbox\.push\.apple\.com\//);
  const bad = await at("/c2p/2", { method: "PUT", body: envelope(2, 2), headers: { "X-Relay-Notify": "loud" } });
  assert.equal(bad.status, 400);
  relay.close();
});

test("A dead device token is dropped; unregistering stops pushes", async () => {
  const { push, sent } = fakeApns(() => ({ status: 410, body: '{"reason":"Unregistered"}' }));
  const relay = createRelay({ apps: RELAY_APPS, push });
  const at = client(relay, CHAT);
  await at.claim();
  await at("/p2c/push", { method: "PUT", body: registration() });
  await at("/p2c/1", { method: "PUT", body: envelope(1, 1), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  await at("/p2c/2", { method: "PUT", body: envelope(1, 2), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  assert.equal(sent.length, 1, "the registration was dropped after 410");

  await at("/p2c/push", { method: "PUT", body: registration() });
  assert.equal((await at("/p2c/push", { method: "DELETE" })).status, 204);
  await at("/p2c/3", { method: "PUT", body: envelope(1, 3), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  assert.equal(sent.length, 1);
  relay.close();
});

test("Pushes per direction are rate limited; a failing APNs never fails the write", async () => {
  let clock = 1_000_000;
  const { push, sent } = fakeApns(() => {
    throw new Error("offline");
  });
  const relay = createRelay({ apps: RELAY_APPS, push, now: () => clock });
  const at = client(relay, CHAT);
  await at.claim();
  await at("/p2c/push", { method: "PUT", body: registration() });
  for (let s = 1; s <= RATES.push.burst + 5; s += 1) {
    const r = await at(`/p2c/${s}`, { method: "PUT", body: envelope(1, s), headers: { "X-Relay-Notify": "alert" } });
    assert.equal(r.status, 201);
  }
  await relay.settled();
  assert.equal(sent.length, RATES.push.burst);
  relay.close();
});

test("Without APNs configured, notify is accepted and ignored", async () => {
  const relay = createRelay({ apps: RELAY_APPS });
  const at = client(relay, CHAT);
  await at.claim();
  assert.equal((await at("/p2c/push", { method: "PUT", body: registration() })).status, 204);
  const r = await at("/p2c/1", { method: "PUT", body: envelope(1, 1), headers: { "X-Relay-Notify": "alert" } });
  assert.equal(r.status, 201);
  relay.close();
});

test("APNs settings must be complete", () => {
  assert.equal(apnsFrom({}, () => {}), null);
  assert.throws(() => apnsFrom({ APNS_TEAM_ID: "TEAM123456" }, () => {}), /APNs/);
  assert.throws(
    () => apnsFrom({ APNS_TEAM_ID: "team", APNS_KEY_ID: "KEY1234567", APNS_PRIVATE_KEY: PEM }, () => {}),
    /APNs/,
  );
});

// ---- ICE -------------------------------------------------------------------

test("ICE servers: STUN, coturn REST credentials and Cloudflare TURN together", async () => {
  const { ice, calls } = fakeIce(() =>
    Response.json({
      iceServers: [
        { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"] },
        { urls: ["turn:turn.cloudflare.com:3478?transport=udp", "turn:turn.cloudflare.com:53?transport=udp"], username: "u", credential: "c" },
      ],
    }),
  );
  const now = 1_700_000_000_000;
  const { iceServers: servers, ttl } = await iceServers(ice, now);
  assert.equal(ttl, 3600);
  assert.deepEqual(servers[0], { urls: ["stun:stun.example.com:3478"] });
  const coturn = servers[1];
  const [expiry] = coturn.username.split(":");
  assert.equal(Number(expiry), now / 1000 + 3600);
  const { createHmac } = await import("node:crypto");
  assert.equal(coturn.credential, createHmac("sha1", "coturn-secret").update(coturn.username).digest("base64"));
  assert.deepEqual(servers[2], { urls: ["stun:stun.cloudflare.com:3478"] });
  assert.deepEqual(servers[3].urls, ["turn:turn.cloudflare.com:3478?transport=udp"]);
  assert.equal(calls[0].url, "https://rtc.live.cloudflare.com/v1/turn/keys/key-id/credentials/generate-ice-servers");
  assert.equal(calls[0].init.headers.Authorization, "Bearer api-token");
  assert.deepEqual(JSON.parse(calls[0].init.body), { ttl: 3600 });
});

test("GET /ice answers servers to the mailbox owner only, and 502 if TURN fails", async () => {
  let up = true;
  const { ice } = fakeIce(() => (up ? Response.json({ iceServers: [] }) : new Response("", { status: 500 })));
  const relay = createRelay({ apps: RELAY_APPS, ice });
  const at = client(relay, CHAT);
  await at.claim();
  const ok = await at("/ice");
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).iceServers.length, 2);
  const stranger = client(relay, CHAT, { ...link(), mailbox: at.link.mailbox });
  assert.equal((await stranger("/ice")).status, 401);
  up = false;
  assert.equal((await at("/ice")).status, 502);
  relay.close();
});

test("ICE settings must be complete and well formed", () => {
  assert.equal(iceFrom({}), null);
  assert.throws(() => iceFrom({ TURN_URLS: "turn:x:3478" }), /ICE/);
  assert.throws(() => iceFrom({ CF_TURN_KEY_ID: "k" }), /ICE/);
  assert.throws(() => iceFrom({ ICE_STUN_URLS: "http://x" }), /ICE/);
});

// ---- signal and watch over real sockets ------------------------------------

let server;
let base;
let directory;
let pushes;

before(async () => {
  directory = mkdtempSync(join(tmpdir(), "zerobyte-ext-"));
  const fake = fakeApns();
  pushes = fake.sent;
  server = createRelayServer({ apps: RELAY_APPS, database: join(directory, "relay.sqlite"), push: fake.push });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(directory, { recursive: true, force: true });
});

function http(l, path, init = {}) {
  return fetch(`http://${base}/v1/${CHAT}/mailbox/${l.mailbox}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${l.bearer}`, ...(init.headers ?? {}) },
  });
}

function open(l, path) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`ws://${base}/v1/${CHAT}/mailbox/${l.mailbox}${path}`, [
      "zerobyte.v1",
      `zerobyte.bearer.${l.bearer}`,
    ]);
    socket.binaryType = "arraybuffer";
    const inbox = [];
    const waiters = [];
    const deliver = (item) => (waiters.length ? waiters.shift()(item) : inbox.push(item));
    socket.onmessage = (event) => deliver(event.data);
    socket.onclose = (event) => deliver({ closed: event.code, reason: event.reason });
    socket.onopen = () =>
      resolve({
        socket,
        next: () => new Promise((done) => (inbox.length ? done(inbox.shift()) : waiters.push(done))),
      });
    socket.onerror = () => reject(new Error("refused"));
  });
}

async function claimed() {
  const l = link();
  const r = await http(l, "", { method: "PUT", body: JSON.stringify({ tokenDigest: l.digest }) });
  assert.equal(r.status, 201);
  return l;
}

test("Signal: both sides hear the other arrive, and binary frames pass through untouched", async () => {
  const l = await claimed();
  const phone = await open(l, "/signal/primary");
  const laptop = await open(l, "/signal/companion");
  assert.equal(await phone.next(), "peer 1");
  assert.equal(await laptop.next(), "peer 1");

  const offer = randomBytes(40_000);
  phone.socket.send(offer);
  assert.deepEqual(Buffer.from(await laptop.next()), offer);
  const answer = randomBytes(300);
  laptop.socket.send(answer);
  assert.deepEqual(Buffer.from(await phone.next()), answer);

  laptop.socket.close();
  assert.equal(await phone.next(), "peer 0");
  phone.socket.close();
});

test("Signal: text frames and oversized frames close the socket; a reconnect replaces the old one", async () => {
  const l = await claimed();
  const first = await open(l, "/signal/primary");
  first.socket.send("hello");
  assert.deepEqual(await first.next(), { closed: 1003, reason: "binary only" });

  const big = await open(l, "/signal/primary");
  big.socket.send(new Uint8Array(65_537));
  assert.equal((await big.next()).closed, 1009);

  const older = await open(l, "/signal/companion");
  const newer = await open(l, "/signal/companion");
  assert.deepEqual(await older.next(), { closed: 4000, reason: "replaced" });
  newer.socket.close();
});

test("Signal needs the mailbox's bearer", async () => {
  const l = await claimed();
  await assert.rejects(open({ ...link(), mailbox: l.mailbox }, "/signal/primary"));
});

test("A watcher that pings is awake, so no push is sent; once it leaves, pushes resume", async () => {
  const l = await claimed();
  await http(l, "/p2c/push", { method: "PUT", body: registration() });
  const watch = await open(l, "/p2c/watch");
  watch.socket.send("ping");
  assert.equal(await watch.next(), "pong");
  const before = pushes.length;
  await http(l, "/p2c/1", { method: "PUT", body: envelope(1, 1), headers: { "X-Relay-Notify": "alert" } });
  assert.equal(await watch.next(), "1");
  await server.relay.settled();
  assert.equal(pushes.length, before);

  watch.socket.close();
  await new Promise((resolve) => setTimeout(resolve, 50));
  await http(l, "/p2c/2", { method: "PUT", body: envelope(1, 2), headers: { "X-Relay-Notify": "alert" } });
  await server.relay.settled();
  assert.equal(pushes.length, before + 1);
});

test("A watcher still only listens: any other frame closes it", async () => {
  const l = await claimed();
  const watch = await open(l, "/c2p/watch");
  watch.socket.send(new Uint8Array([1, 2, 3]));
  assert.deepEqual(await watch.next(), { closed: 1003, reason: "listen only" });
});

test("Erasing closes signal sockets too", async () => {
  const l = await claimed();
  const phone = await open(l, "/signal/primary");
  assert.equal((await http(l, "", { method: "DELETE" })).status, 204);
  assert.deepEqual(await phone.next(), { closed: 1000, reason: "erased" });
});
