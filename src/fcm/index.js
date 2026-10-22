// FCM: the push provider for Android apps (Firebase Cloud Messaging, HTTP v1).
//
// A separate module, like src/apns/: the relay core knows only the provider
// interface in push.js. A relay that serves no Android app leaves
// FCM_SERVICE_ACCOUNT unset and never loads Google credentials.
//
// Registration fields: token (the FCM registration token).
//
// Every message is data-only, so the app's FirebaseMessagingService always
// receives it and draws the notification itself after fetching and opening
// the envelope. Data keys: zerobyte_tag, zerobyte_notify ("alert" or
// "silent") and, for alerts, zerobyte_alert (the text to show if the app
// cannot open the envelope in time).

import { fromBase64, toBase64url, utf8 } from "../bytes.js";

export const FCM = Object.freeze({
  alertLifetimeSeconds: 7 * 24 * 60 * 60,
  silentLifetimeSeconds: 60 * 60,
  // Google's access tokens last an hour; refresh ten minutes early.
  accessTokenMilliseconds: 50 * 60 * 1000,
  defaultAlert: "New message",
  scope: "https://www.googleapis.com/auth/firebase.messaging",
  tokenURL: "https://oauth2.googleapis.com/token",
});

const REGISTRATION_TOKEN = /^[A-Za-z0-9_:-]{32,1024}$/;
const PROJECT = /^[a-z][a-z0-9-]{4,61}[a-z0-9]$/;

/**
 * The FCM provider from the environment, or null when it is not configured.
 * `FCM_SERVICE_ACCOUNT` is the service account's JSON key, as downloaded from
 * the Firebase console. `post({ url, headers, body })` resolves to
 * `{ status, body }`; the default uses fetch, which both runtimes have.
 */
export function fcmFrom(source, post = fetchPost) {
  const json = source?.FCM_SERVICE_ACCOUNT ?? "";
  if (!json) return null;
  let account;
  try {
    account = JSON.parse(json);
  } catch {
    account = null;
  }
  const projectId = account?.project_id;
  const clientEmail = account?.client_email;
  const privateKey = account?.private_key;
  if (
    typeof projectId !== "string" ||
    !PROJECT.test(projectId) ||
    typeof clientEmail !== "string" ||
    !clientEmail.includes("@") ||
    typeof privateKey !== "string" ||
    !privateKey.includes("PRIVATE KEY")
  ) {
    throw new Error(
      "FCM: FCM_SERVICE_ACCOUNT must be the service account JSON key with project_id, client_email and private_key",
    );
  }
  const state = { projectId, clientEmail, privateKey, post, cached: null };
  return {
    service: "fcm",
    parse: parseFields,
    send: (topic, registration, kind, now = Date.now()) => sendPush(state, registration, kind, now),
    state,
  };
}

/** `{ token }`, or null when it is not valid. */
export function parseFields({ token }) {
  if (typeof token !== "string" || !REGISTRATION_TOKEN.test(token)) return null;
  return { token };
}

function pkcs8(pem) {
  return fromBase64(
    pem
      .replace(/-----[^-]+-----/g, "")
      .replace(/\\n/g, "")
      .replace(/\s+/g, ""),
  );
}

/** The signed RS256 assertion Google exchanges for an access token. */
export async function assertion(state, now) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8(state.privateKey),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const iat = Math.floor(now / 1000);
  const header = toBase64url(utf8.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claims = toBase64url(
    utf8.encode(
      JSON.stringify({
        iss: state.clientEmail,
        scope: FCM.scope,
        aud: FCM.tokenURL,
        iat,
        exp: iat + 3600,
      }),
    ),
  );
  const input = `${header}.${claims}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, utf8.encode(input));
  return `${input}.${toBase64url(signature)}`;
}

/** An OAuth access token for FCM, reused for 50 minutes. */
export function accessToken(state, now) {
  if (state.cached && now - state.cached.at < FCM.accessTokenMilliseconds) return state.cached.value;
  const value = (async () => {
    const response = await state.post({
      url: FCM.tokenURL,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: await assertion(state, now),
      }).toString(),
    });
    const token = response.status === 200 ? JSON.parse(response.body).access_token : null;
    if (typeof token !== "string") throw new Error(`FCM: token endpoint answered ${response.status}`);
    return token;
  })();
  state.cached = { at: now, value };
  value.catch(() => {
    if (state.cached?.value === value) state.cached = null;
  });
  return value;
}

/** The FCM request for one notification. */
export async function fcmRequest(state, registration, kind, now) {
  const alert = kind === "alert";
  const data = { zerobyte_tag: registration.tag, zerobyte_notify: kind };
  if (alert) data.zerobyte_alert = registration.alert ?? FCM.defaultAlert;
  const lifetime = alert ? FCM.alertLifetimeSeconds : FCM.silentLifetimeSeconds;
  return {
    url: `https://fcm.googleapis.com/v1/projects/${state.projectId}/messages:send`,
    headers: {
      authorization: `Bearer ${await accessToken(state, now)}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      message: {
        token: registration.token,
        data,
        android: { priority: alert ? "high" : "normal", ttl: `${lifetime}s` },
      },
    }),
  };
}

/**
 * Sends one notification. Resolves to `{ status, reason, gone }`; `gone` means
 * the registration token is dead. Never throws.
 */
async function sendPush(state, registration, kind, now) {
  try {
    const response = await state.post(await fcmRequest(state, registration, kind, now));
    let reason = "";
    try {
      const error = JSON.parse(response.body || "{}").error;
      reason =
        error?.details?.find?.((d) => typeof d?.errorCode === "string")?.errorCode ?? error?.status ?? "";
    } catch {
      // A success body holds only the message name.
    }
    if (response.status === 401) state.cached = null;
    const gone = reason === "UNREGISTERED" || reason === "SENDER_ID_MISMATCH";
    return { status: response.status, reason, gone };
  } catch {
    return { status: 0, reason: "unreachable", gone: false };
  }
}

/** `post` over fetch: Cloudflare Workers and Node 20+ both have it. */
export async function fetchPost({ url, headers, body }) {
  const response = await fetch(url, { method: "POST", headers, body });
  return { status: response.status, body: await response.text() };
}
