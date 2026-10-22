// APNs: the push provider for iOS, iPadOS, macOS and watchOS apps.
//
// A separate module on purpose: the relay core (core.js, push.js) knows only
// the provider interface below and nothing about Apple. A relay that serves no
// Apple app never loads this file's settings, and a dedicated app can replace
// it with its own provider.
//
// Provider interface (see push.js):
//   service                       "apns"
//   parse(fields)                 the provider's registration fields, checked, or null
//   send(topic, registration, kind, now)   resolves to { status, reason, gone }; never throws
//   close()                       optional, releases connections
//
// Registration fields: token (the device token, lower-case hex) and
// environment ("production" or "development", which APNs host to use).

import { fromBase64, toBase64url, utf8 } from "../bytes.js";

export const APNS = Object.freeze({
  alertLifetimeSeconds: 7 * 24 * 60 * 60,
  silentLifetimeSeconds: 60 * 60,
  // Apple: reuse a provider token for at least 20 and at most 60 minutes.
  providerTokenMilliseconds: 40 * 60 * 1000,
  defaultAlert: "New message",
});

const DEVICE_TOKEN = /^(?:[0-9a-f]{2}){32,100}$/;
const TEN = /^[A-Z0-9]{10}$/;

/**
 * The APNs provider from the environment, or null when it is not configured.
 * `deliver({ url, headers, body })` must speak HTTP/2 and resolve to
 * `{ status, body }`: `fetchDeliver` on Cloudflare Workers, `http2Deliver`
 * (apns/node.js) on Node.
 */
export function apnsFrom(source, deliver) {
  const teamId = source?.APNS_TEAM_ID ?? "";
  const keyId = source?.APNS_KEY_ID ?? "";
  const privateKey = source?.APNS_PRIVATE_KEY ?? "";
  if (!teamId && !keyId && !privateKey) return null;
  if (!TEN.test(teamId) || !TEN.test(keyId) || !privateKey.includes("PRIVATE KEY")) {
    throw new Error(
      "APNs: set APNS_TEAM_ID and APNS_KEY_ID (10 characters each) and APNS_PRIVATE_KEY (the .p8 file) together",
    );
  }
  const state = { teamId, keyId, privateKey, deliver, cached: null };
  return {
    service: "apns",
    parse: parseFields,
    send: (topic, registration, kind, now = Date.now()) =>
      sendPush(state, topic, registration, kind, now),
    close: () => deliver?.close?.(),
    state,
  };
}

/** `{ token, environment }`, or null when they are not valid. */
export function parseFields({ token, environment }) {
  if (typeof token !== "string" || !DEVICE_TOKEN.test(token)) return null;
  if (environment !== "production" && environment !== "development") return null;
  return { token, environment };
}

function pkcs8(pem) {
  const body = pem
    .replace(/-----[^-]+-----/g, "")
    .replace(/\\n/g, "")
    .replace(/\s+/g, "");
  return fromBase64(body);
}

/** The ES256 provider token (JWT), reused for 40 minutes. */
export function providerToken(state, now) {
  if (state.cached && now - state.cached.at < APNS.providerTokenMilliseconds) {
    return state.cached.value;
  }
  const value = (async () => {
    const key = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8(state.privateKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const header = toBase64url(utf8.encode(JSON.stringify({ alg: "ES256", kid: state.keyId })));
    const claims = toBase64url(
      utf8.encode(JSON.stringify({ iss: state.teamId, iat: Math.floor(now / 1000) })),
    );
    const input = `${header}.${claims}`;
    // WebCrypto returns the raw r ‖ s form that JWS ES256 uses.
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      utf8.encode(input),
    );
    return `${input}.${toBase64url(signature)}`;
  })();
  state.cached = { at: now, value };
  value.catch(() => {
    if (state.cached?.value === value) state.cached = null;
  });
  return value;
}

/** The APNs request for one notification. */
export async function apnsRequest(state, topic, registration, kind, now) {
  const alert = kind === "alert";
  const host =
    registration.environment === "production"
      ? "https://api.push.apple.com"
      : "https://api.sandbox.push.apple.com";
  const payload = alert
    ? {
        aps: {
          alert: { body: registration.alert ?? APNS.defaultAlert },
          "mutable-content": 1,
          sound: "default",
        },
        zerobyte: { tag: registration.tag },
      }
    : { aps: { "content-available": 1 }, zerobyte: { tag: registration.tag } };
  const lifetime = alert ? APNS.alertLifetimeSeconds : APNS.silentLifetimeSeconds;
  return {
    url: `${host}/3/device/${registration.token}`,
    headers: {
      authorization: `bearer ${await providerToken(state, now)}`,
      "apns-topic": topic,
      "apns-push-type": alert ? "alert" : "background",
      "apns-priority": alert ? "10" : "5",
      "apns-expiration": String(Math.floor(now / 1000) + lifetime),
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  };
}

/**
 * Sends one notification. Resolves to `{ status, reason, gone }`, where `gone`
 * means the device token is dead and the registration should be dropped.
 * Never throws.
 */
async function sendPush(state, topic, registration, kind, now) {
  try {
    const response = await state.deliver(await apnsRequest(state, topic, registration, kind, now));
    let reason = "";
    try {
      reason = JSON.parse(response.body || "{}").reason ?? "";
    } catch {
      // APNs answers 200 with an empty body.
    }
    if (response.status === 403 && /ProviderToken/.test(reason)) state.cached = null;
    const gone =
      response.status === 410 ||
      (response.status === 400 && (reason === "BadDeviceToken" || reason === "DeviceTokenNotForTopic"));
    return { status: response.status, reason, gone };
  } catch {
    return { status: 0, reason: "unreachable", gone: false };
  }
}

/** `deliver` for Cloudflare Workers, whose fetch negotiates HTTP/2 with APNs. */
export async function fetchDeliver({ url, headers, body }) {
  const response = await fetch(url, { method: "POST", headers, body });
  return { status: response.status, body: await response.text() };
}
