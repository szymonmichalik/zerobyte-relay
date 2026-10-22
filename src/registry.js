// Apps registered at run time, for a hosted relay whose console signs apps up.
//
// The console writes two kinds of keys to a KV namespace bound as `REGISTRY`:
//
//   apps:index   {"apps": ["<app id>", …]}: every app that exists
//   app:<id>     {"name", "options", "status", "secrets"}
//
// `options` is written as in RELAY_APPS (`push=com.example.app;signal`),
// `status` is "active" or "suspended" (writes answer 402), and `secrets` is the
// app's own push credentials, sealed with AES-256-GCM under `REGISTRY_KEY`
// (32 bytes, base64) with the app id as additional data, so an entry cannot be
// moved to another app. The relay never writes to the namespace.
//
// Each isolate reads the index at most once a minute and an app's entry at
// most once a minute, so a request for a made-up app id costs no KV read, and
// a change in the console reaches the relay within about two minutes.

import { appProfile } from "./apps.js";
import { apnsFrom, fetchDeliver } from "./apns/index.js";
import { fromBase64, toBase64, utf8 } from "./bytes.js";
import { fcmFrom } from "./fcm/index.js";
import { pushProviders } from "./push.js";

export const REGISTRY = Object.freeze({ cacheMilliseconds: 60_000 });

async function secretKey(keyBase64, usage) {
  let raw = null;
  try {
    raw = fromBase64(keyBase64 ?? "");
  } catch {
    // Reported below with the same message.
  }
  if (raw?.length !== 32) throw new Error("REGISTRY_KEY must be 32 bytes, base64");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}

/** Seals an app's secrets for its registry entry: `{ iv, data }`, both base64. */
export async function sealSecrets(keyBase64, app, secrets) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8.encode(app) },
    await secretKey(keyBase64, "encrypt"),
    utf8.encode(JSON.stringify(secrets)),
  );
  return { iv: toBase64(iv), data: toBase64(data) };
}

/** Opens what `sealSecrets` sealed for the same app; throws otherwise. */
export async function openSecrets(keyBase64, app, sealed) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(sealed.iv), additionalData: utf8.encode(app) },
    await secretKey(keyBase64, "decrypt"),
    fromBase64(sealed.data),
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

/** Push providers from an app's own credentials, or null when it has none. */
function providersFrom({ apns, fcm } = {}, deliver) {
  return pushProviders(
    apns ? apnsFrom({ APNS_TEAM_ID: apns.teamId, APNS_KEY_ID: apns.keyId, APNS_PRIVATE_KEY: apns.privateKey }, deliver) : null,
    fcm ? fcmFrom({ FCM_SERVICE_ACCOUNT: fcm }) : null,
  );
}

/**
 * The registry over a KV namespace, or null without one. `lookup(id)`
 * resolves to `{ profile, push }` for a registered app (`push` is null when
 * the app has no credentials of its own), or null.
 */
export function registryFrom(kv, keyBase64, { now = () => Date.now(), deliver = fetchDeliver } = {}) {
  if (!kv) return null;
  let index = null;
  const entries = new Map();

  async function known(id) {
    if (!index || now() - index.at >= REGISTRY.cacheMilliseconds) {
      const value = await kv.get("apps:index", "json").catch(() => null);
      index = { at: now(), ids: new Set(Array.isArray(value?.apps) ? value.apps : []) };
    }
    return index.ids.has(id);
  }

  async function load(id) {
    const value = await kv.get(`app:${id}`, "json").catch(() => null);
    if (!value) return null;
    try {
      const profile = appProfile(id, value.name ?? "", value.options ?? "", value.status ?? "active");
      const secrets = value.secrets && keyBase64 ? await openSecrets(keyBase64, id, value.secrets) : null;
      return { profile, push: secrets ? providersFrom(secrets, deliver) : null };
    } catch {
      // A broken entry is an unregistered app, never a crashed relay.
      return null;
    }
  }

  return {
    async lookup(id) {
      if (!(await known(id))) return null;
      const cached = entries.get(id);
      if (cached && now() - cached.at < REGISTRY.cacheMilliseconds) return cached.entry;
      const entry = await load(id);
      entries.set(id, { at: now(), entry });
      return entry;
    },
  };
}
