// Apps signed up through a console: the KV registry, sealed per-app secrets,
// suspended apps, and the Worker's routing of registry apps.

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";

import worker from "../src/cloudflare.js";
import { appProfile } from "../src/apps.js";
import { openSecrets, REGISTRY, registryFrom, sealSecrets } from "../src/registry.js";
import { createRelay } from "../src/node/server.js";

const APP = "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8";
const OTHER = "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e9";
const KEY = randomBytes(32).toString("base64");
const PEM = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" });

function fakeKV(values) {
  const reads = [];
  return {
    reads,
    values,
    async get(key, type) {
      reads.push(key);
      const value = values[key];
      if (value === undefined) return null;
      return type === "json" ? JSON.parse(JSON.stringify(value)) : JSON.stringify(value);
    },
  };
}

test("Secrets are sealed to one app and open only for it", async () => {
  const sealed = await sealSecrets(KEY, APP, { fcm: "{}" });
  assert.deepEqual(await openSecrets(KEY, APP, sealed), { fcm: "{}" });
  await assert.rejects(openSecrets(KEY, OTHER, sealed));
  await assert.rejects(openSecrets(randomBytes(32).toString("base64"), APP, sealed));
  await assert.rejects(sealSecrets("short", APP, {}), /32 bytes/);
});

test("Only indexed apps are looked up, and both reads are cached for a minute", async () => {
  let clock = 0;
  const kv = fakeKV({
    "apps:index": { apps: [APP] },
    [`app:${APP}`]: { name: "chat", options: "push=com.example.chat;signal", status: "active" },
  });
  const registry = registryFrom(kv, KEY, { now: () => clock });
  const entry = await registry.lookup(APP);
  assert.equal(entry.profile.features.push, "com.example.chat");
  assert.equal(entry.profile.features.signal, true);
  assert.equal(entry.profile.status, "active");
  assert.equal(entry.push, null);
  assert.equal(await registry.lookup(OTHER), null, "not in the index: no entry read");
  await registry.lookup(APP);
  assert.deepEqual(kv.reads, ["apps:index", `app:${APP}`]);

  kv.values[`app:${APP}`].status = "suspended";
  clock += REGISTRY.cacheMilliseconds;
  assert.equal((await registry.lookup(APP)).profile.status, "suspended");
  assert.equal(registryFrom(null, KEY), null);
});

test("An app's own push credentials become its providers; a broken entry is no app", async () => {
  const secrets = await sealSecrets(KEY, APP, {
    apns: { teamId: "TEAM123456", keyId: "KEY1234567", privateKey: PEM },
  });
  const kv = fakeKV({
    "apps:index": { apps: [APP, OTHER] },
    [`app:${APP}`]: { name: "a", options: "push=com.example.a", status: "active", secrets },
    [`app:${OTHER}`]: { name: "b", options: "envelopes=1", status: "active" },
  });
  const registry = registryFrom(kv, KEY);
  assert.deepEqual(Object.keys((await registry.lookup(APP)).push), ["apns"]);
  assert.equal(await registry.lookup(OTHER), null);
  assert.equal(await registryFrom(kv, randomBytes(32).toString("base64")).lookup(APP), null, "wrong key");
});

test("A suspended app's writes answer 402; it can still read, prune and erase", async () => {
  const relay = createRelay({ apps: { [APP]: appProfile(APP, "chat", "", "suspended") } });
  const token = randomBytes(32);
  const mailbox = randomBytes(16).toString("hex");
  const at = (path, init = {}) =>
    relay.fetch(
      new Request(`http://relay.invalid/v1/${APP}/mailbox/${mailbox}${path}`, {
        ...init,
        headers: { Authorization: `Bearer ${token.toString("base64url")}` },
      }),
    );
  const digest = createHash("sha256").update(token).digest("hex");
  assert.equal((await at("", { method: "PUT", body: JSON.stringify({ tokenDigest: digest }) })).status, 201);
  const envelope = new Uint8Array(64);
  envelope[0] = 1;
  envelope[1] = 1;
  envelope[9] = 1;
  const refused = await at("/p2c/1", { method: "PUT", body: envelope });
  assert.equal(refused.status, 402);
  assert.deepEqual(await refused.json(), { error: "payment_required", status: 402 });
  assert.equal((await at("/p2c")).status, 200);
  assert.equal((await at("/p2c?through=1", { method: "DELETE" })).status, 204);
  assert.equal((await at("", { method: "DELETE" })).status, 204);
  relay.close();
  assert.throws(() => appProfile(APP, "x", "", "paused"), /status/);
  assert.throws(() => appProfile("nope", "x", ""), /UUIDv7/);
});

test("The Worker routes a registry app to its mailbox and keeps unknown apps out", async () => {
  const seen = [];
  const env = {
    RELAY_APPS: "",
    REGISTRY: fakeKV({
      "apps:index": { apps: [APP] },
      [`app:${APP}`]: { name: "chat", options: "", status: "active" },
    }),
    REGISTRY_KEY: KEY,
    MAILBOX: {
      idFromName: (name) => name,
      get: (id) => ({
        fetch: async () => {
          seen.push(id);
          return new Response(null, { status: 204 });
        },
      }),
    },
  };
  const mailbox = randomBytes(16).toString("hex");
  const call = (app) =>
    worker.fetch(
      new Request(`https://relay.invalid/v1/${app}/mailbox/${mailbox}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${randomBytes(32).toString("base64url")}` },
      }),
      env,
    );
  assert.equal((await call(APP)).status, 204);
  assert.deepEqual(seen, [`${APP}/${mailbox}`]);
  assert.equal((await call(OTHER)).status, 404);
});
