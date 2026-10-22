// Push: waking a device that is not watching, through a push provider.
//
// The device that reads a direction registers for that direction with one push
// service. When the other device stores an envelope there and asks for a
// notification (`X-Relay-Notify`), and nobody is watching the direction, the
// relay hands one content-free notification to that service's provider. The
// device then fetches and opens the envelope itself.
//
// This file knows no push service. Providers are separate modules, given to
// the relay at start-up as `env.PUSH = { <service>: provider }`; APNs lives in
// src/apns/ and FCM in src/fcm/. A provider is:
//
//   service                               its name, as in a registration
//   parse(fields)                         its own registration fields, checked, or null
//   send(topic, registration, kind, now)  resolves to { status, reason, gone }; never throws
//   close()                               optional
//
// What a notification carries: a fixed alert text the device chose at
// registration (shown only if the app cannot replace it), and an opaque tag the
// device chose, so it knows which link to fetch without the relay or the push
// service learning the mailbox. Never envelope bytes, never a sequence number.
//
// At rest the registration is sealed with AES-256-GCM under a key derived from
// the mailbox's bearer token. The relay stores only the token's SHA-256, so a
// copy of its database does not reveal device tokens, and cannot be used to
// link the mailboxes of one device. The relay opens the registration only
// while it serves a request that presents the bearer.

import { fromBase64, toBase64, fromBase64url, utf8 } from "./bytes.js";

export const PUSH = Object.freeze({
  registrationBytes: 2048,
  alertCharacters: 160,
  // Without a provider for its service a registration is kept, so a device can
  // register before the operator configures one; these bound what it may hold.
  unknownFields: 8,
  unknownFieldCharacters: 256,
});

/** The values of `X-Relay-Notify`. */
export const NOTIFY = Object.freeze(["alert", "silent"]);

const TAG = /^[A-Za-z0-9_-]{1,64}$/;
const SERVICE = /^[a-z][a-z0-9-]{0,15}$/;
const TOPIC = /^[A-Za-z0-9][A-Za-z0-9.-]{0,154}$/;
const GENERIC = new Set(["service", "tag", "alert"]);

/** A push topic in RELAY_APPS: for APNs, the app's bundle id; FCM ignores it. */
export function isTopic(text) {
  return typeof text === "string" && TOPIC.test(text);
}

/**
 * A registration body, or null when it is not one:
 * {"service": "<name>", "tag": "<1-64 of A-Z a-z 0-9 _ ->",
 *  "alert": "<optional, at most 160 characters>", ...the service's own fields}
 * `providers` is `env.PUSH`; the provider for the service checks its fields.
 */
export function parseRegistration(bytes, providers = null) {
  if (!bytes || bytes.length === 0 || bytes.length > PUSH.registrationBytes) return null;
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const { service, tag, alert } = value;
  if (typeof service !== "string" || !SERVICE.test(service)) return null;
  if (typeof tag !== "string" || !TAG.test(tag)) return null;
  if (alert !== undefined) {
    if (typeof alert !== "string" || alert.length === 0) return null;
    if ([...alert].length > PUSH.alertCharacters) return null;
  }
  const rest = Object.fromEntries(Object.entries(value).filter(([key]) => !GENERIC.has(key)));
  const provider = providers?.[service];
  let fields;
  if (provider) {
    fields = provider.parse(rest);
    if (!fields || Object.keys(rest).some((key) => !(key in fields))) return null;
  } else {
    const entries = Object.entries(rest);
    if (entries.length > PUSH.unknownFields) return null;
    const plain = ([, v]) => typeof v === "string" && v.length <= PUSH.unknownFieldCharacters;
    if (!entries.every(plain)) return null;
    fields = rest;
  }
  const registration = { service, ...fields, tag };
  if (alert !== undefined) registration.alert = alert;
  return registration;
}

async function registrationKey(bearer, mailbox, direction) {
  const base = await crypto.subtle.importKey("raw", fromBase64url(bearer), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8.encode("zerobyte-push-v1"),
      info: utf8.encode(`${mailbox}/${direction}`),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Seals a registration for storage: `{ iv, data }`, both base64. */
export async function sealRegistration(bearer, mailbox, direction, registration) {
  const key = await registrationKey(bearer, mailbox, direction);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    utf8.encode(JSON.stringify(registration)),
  );
  return { iv: toBase64(iv), data: toBase64(data) };
}

/** Opens a stored registration; throws if the bearer is not the one that sealed it. */
export async function openRegistration(bearer, mailbox, direction, sealed) {
  const key = await registrationKey(bearer, mailbox, direction);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(sealed.iv) },
    key,
    fromBase64(sealed.data),
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

/** `env.PUSH` from a list of providers, leaving out the ones not configured. */
export function pushProviders(...providers) {
  const map = {};
  for (const provider of providers) {
    if (!provider) continue;
    if (map[provider.service]) throw new Error(`push: two providers for ${provider.service}`);
    map[provider.service] = provider;
  }
  return Object.keys(map).length ? map : null;
}
