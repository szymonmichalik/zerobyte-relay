// The FCM push provider: registration, the OAuth exchange, the message it
// sends and what it does with FCM's answers. Google is a stand-in; nothing
// leaves the machine.

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { test } from "node:test";

import { apnsFrom } from "../src/apns/index.js";
import { fcmFrom } from "../src/fcm/index.js";
import { parseRegistration, pushProviders } from "../src/push.js";
import { createRelay } from "../src/node/server.js";

const APP = "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8";
const RELAY_APPS = `${APP}=chat;push=com.example.chat`;
const TOKEN = `cX9${"a".repeat(60)}:APA91b${"B_-".repeat(30)}`;

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ACCOUNT = JSON.stringify({
  type: "service_account",
  project_id: "zerobyte-test",
  client_email: "relay@zerobyte-test.iam.gserviceaccount.com",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
});

function fakeGoogle(answer = () => ({ status: 200, body: '{"name":"projects/zerobyte-test/messages/1"}' })) {
  const sent = [];
  const tokens = [];
  const post = async (request) => {
    if (request.url === "https://oauth2.googleapis.com/token") {
      tokens.push(request);
      return { status: 200, body: JSON.stringify({ access_token: `ya29.${tokens.length}`, expires_in: 3599 }) };
    }
    sent.push(request);
    return answer(request);
  };
  const fcm = fcmFrom({ FCM_SERVICE_ACCOUNT: ACCOUNT }, post);
  return { fcm, push: pushProviders(fcm), sent, tokens };
}

function link() {
  const token = randomBytes(32);
  return {
    mailbox: randomBytes(16).toString("hex"),
    bearer: token.toString("base64url"),
    digest: createHash("sha256").update(token).digest("hex"),
  };
}

function client(relay, l = link()) {
  const at = (path, { method = "GET", body, headers = {} } = {}) =>
    relay.fetch(
      new Request(`http://relay.invalid/v1/${APP}/mailbox/${l.mailbox}${path}`, {
        method,
        body,
        headers: { Authorization: `Bearer ${l.bearer}`, ...headers },
      }),
    );
  at.link = l;
  at.claim = () => at("", { method: "PUT", body: JSON.stringify({ tokenDigest: l.digest }) });
  return at;
}

function envelope(sequence) {
  const bytes = new Uint8Array(64);
  bytes[0] = 1;
  bytes[1] = 1;
  new DataView(bytes.buffer).setBigUint64(2, BigInt(sequence));
  return bytes;
}

const registration = (extra = {}) => JSON.stringify({ service: "fcm", token: TOKEN, tag: "team-3", ...extra });

test("FCM registrations are validated strictly", () => {
  const { push } = fakeGoogle();
  const parse = (text) => parseRegistration(new TextEncoder().encode(text), push);
  assert.deepEqual(parse(registration()), { service: "fcm", token: TOKEN, tag: "team-3" });
  for (const bad of [
    registration({ token: "short" }),
    registration({ token: "has space ".repeat(10) }),
    registration({ environment: "production" }),
    registration({ token: 42 }),
  ]) {
    assert.equal(parse(bad), null, bad);
  }
});

test("A notify wakes an Android reader with one data-only FCM message", async () => {
  const { push, sent, tokens } = fakeGoogle();
  const relay = createRelay({ apps: RELAY_APPS, push });
  const at = client(relay);
  await at.claim();
  assert.equal((await at("/p2c/push", { method: "PUT", body: registration({ alert: "New data" }) })).status, 204);

  await at("/p2c/1", { method: "PUT", body: envelope(1), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  assert.equal(sent.length, 1);
  const [pushed] = sent;
  assert.equal(pushed.url, "https://fcm.googleapis.com/v1/projects/zerobyte-test/messages:send");
  assert.equal(pushed.headers.authorization, "Bearer ya29.1");
  assert.deepEqual(JSON.parse(pushed.body), {
    message: {
      token: TOKEN,
      data: { zerobyte_tag: "team-3", zerobyte_notify: "alert", zerobyte_alert: "New data" },
      android: { priority: "high", ttl: "604800s" },
    },
  });
  assert.ok(!pushed.body.includes(at.link.mailbox), "the push does not name the mailbox");

  // The assertion is an RS256 JWT for the FCM scope, signed by the service account.
  const form = new URLSearchParams(tokens[0].body);
  assert.equal(form.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
  const [h, c, s] = form.get("assertion").split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url")), { alg: "RS256", typ: "JWT" });
  const claims = JSON.parse(Buffer.from(c, "base64url"));
  assert.equal(claims.iss, "relay@zerobyte-test.iam.gserviceaccount.com");
  assert.equal(claims.scope, "https://www.googleapis.com/auth/firebase.messaging");
  assert.equal(claims.aud, "https://oauth2.googleapis.com/token");
  assert.equal(claims.exp - claims.iat, 3600);
  assert.ok(verify("sha256", Buffer.from(`${h}.${c}`), publicKey, Buffer.from(s, "base64url")));

  await at("/p2c/2", { method: "PUT", body: envelope(2), headers: { "X-Relay-Notify": "silent" } });
  await relay.settled();
  assert.deepEqual(JSON.parse(sent[1].body).message, {
    token: TOKEN,
    data: { zerobyte_tag: "team-3", zerobyte_notify: "silent" },
    android: { priority: "normal", ttl: "3600s" },
  });
  assert.equal(tokens.length, 1, "the access token is reused");
  relay.close();
});

test("An alert without registered text carries the default", async () => {
  const { fcm, sent } = fakeGoogle();
  await fcm.send("com.example.chat", { token: TOKEN, tag: "t" }, "alert", 0);
  assert.equal(JSON.parse(sent[0].body).message.data.zerobyte_alert, "New message");
});

test("An unregistered FCM token is dropped; other errors keep it", async () => {
  const unregistered = {
    status: 404,
    body: JSON.stringify({
      error: {
        code: 404,
        status: "NOT_FOUND",
        details: [{ "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode: "UNREGISTERED" }],
      },
    }),
  };
  let answer = { status: 503, body: '{"error":{"code":503,"status":"UNAVAILABLE"}}' };
  const { push, sent } = fakeGoogle(() => answer);
  const relay = createRelay({ apps: RELAY_APPS, push });
  const at = client(relay);
  await at.claim();
  await at("/p2c/push", { method: "PUT", body: registration() });
  await at("/p2c/1", { method: "PUT", body: envelope(1), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  answer = unregistered;
  await at("/p2c/2", { method: "PUT", body: envelope(2), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  await at("/p2c/3", { method: "PUT", body: envelope(3), headers: { "X-Relay-Notify": "alert" } });
  await relay.settled();
  assert.equal(sent.length, 2, "kept after 503, dropped after UNREGISTERED");
  relay.close();
});

test("A rejected access token is fetched again; an unreachable Google never fails the write", async () => {
  let status = 401;
  const { fcm, tokens } = fakeGoogle(() => ({ status, body: "{}" }));
  assert.deepEqual(await fcm.send("t", { token: TOKEN, tag: "t" }, "silent", 0), {
    status: 401,
    reason: "",
    gone: false,
  });
  status = 200;
  await fcm.send("t", { token: TOKEN, tag: "t" }, "silent", 1000);
  assert.equal(tokens.length, 2);

  const offline = fcmFrom({ FCM_SERVICE_ACCOUNT: ACCOUNT }, async () => {
    throw new Error("offline");
  });
  assert.deepEqual(await offline.send("t", { token: TOKEN, tag: "t" }, "alert", 0), {
    status: 0,
    reason: "unreachable",
    gone: false,
  });
});

test("FCM settings must be a service account key", () => {
  assert.equal(fcmFrom({}), null);
  for (const bad of [
    "not json",
    JSON.stringify({ project_id: "zerobyte-test" }),
    JSON.stringify({ ...JSON.parse(ACCOUNT), private_key: "nope" }),
    JSON.stringify({ ...JSON.parse(ACCOUNT), project_id: "Bad Project" }),
  ]) {
    assert.throws(() => fcmFrom({ FCM_SERVICE_ACCOUNT: bad }), /FCM/);
  }
});

test("APNs and FCM serve one relay side by side", () => {
  const { fcm } = fakeGoogle();
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" });
  const apns = apnsFrom({ APNS_TEAM_ID: "TEAM123456", APNS_KEY_ID: "KEY1234567", APNS_PRIVATE_KEY: ec }, () => {});
  assert.deepEqual(Object.keys(pushProviders(apns, fcm)).sort(), ["apns", "fcm"]);
});
