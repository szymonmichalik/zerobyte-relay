// ICE servers for a direct connection between the two devices of a link.
//
// Devices that want to talk directly (WebRTC, or any ICE implementation)
// exchange offers and candidates over the signal socket and need STUN, and
// TURN for networks where a direct path is impossible. TURN credentials are
// short-lived and minted here, so the long-term TURN secret never ships in an
// app. Three sources, any combination:
//
//   ICE_STUN_URLS                     STUN only, comma-separated
//   TURN_URLS + TURN_SECRET           your coturn (`use-auth-secret`):
//                                     username "<expiry>:<random>", HMAC-SHA1 password
//   CF_TURN_KEY_ID + CF_TURN_API_TOKEN  Cloudflare Realtime TURN
//
// TURN relays the devices' DTLS-encrypted traffic; it never sees plaintext.

import { toBase64, toHex, utf8 } from "./bytes.js";

export const ICE = Object.freeze({ ttlSeconds: 3600 });

function list(text) {
  return String(text ?? "")
    .split(/[,\s]+/)
    .filter(Boolean);
}

const URL_PATTERN = /^(stun|stuns|turn|turns):[^\s,]+$/;

/** ICE settings from the environment, or null when none are set. */
export function iceFrom(source, fetcher = (...args) => fetch(...args)) {
  const stun = list(source?.ICE_STUN_URLS);
  const turnUrls = list(source?.TURN_URLS);
  const secret = source?.TURN_SECRET ?? "";
  const keyId = source?.CF_TURN_KEY_ID ?? "";
  const apiToken = source?.CF_TURN_API_TOKEN ?? "";
  for (const url of [...stun, ...turnUrls]) {
    if (!URL_PATTERN.test(url)) throw new Error(`ICE: "${url}" is not a stun:, stuns:, turn: or turns: URL`);
  }
  if (Boolean(secret) !== turnUrls.length > 0) {
    throw new Error("ICE: set TURN_URLS and TURN_SECRET together");
  }
  if (Boolean(keyId) !== Boolean(apiToken)) {
    throw new Error("ICE: set CF_TURN_KEY_ID and CF_TURN_API_TOKEN together");
  }
  if (!stun.length && !secret && !keyId) return null;
  return {
    stun,
    turn: secret ? { urls: turnUrls, secret } : null,
    cloudflare: keyId ? { keyId, apiToken } : null,
    fetch: fetcher,
  };
}

async function hmacSha1(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    utf8.encode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  return toBase64(await crypto.subtle.sign("HMAC", key, utf8.encode(text)));
}

/** `{ iceServers, ttl }` in the RTCIceServer shape. Throws if a provider fails. */
export async function iceServers(ice, now = Date.now()) {
  const ttl = ICE.ttlSeconds;
  const servers = [];
  if (ice.stun.length) servers.push({ urls: ice.stun });
  if (ice.turn) {
    const username = `${Math.floor(now / 1000) + ttl}:${toHex(crypto.getRandomValues(new Uint8Array(8)))}`;
    servers.push({ urls: ice.turn.urls, username, credential: await hmacSha1(ice.turn.secret, username) });
  }
  if (ice.cloudflare) {
    const response = await ice.fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(ice.cloudflare.keyId)}/credentials/generate-ice-servers`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${ice.cloudflare.apiToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ttl }),
      },
    );
    if (!response.ok) throw new Error(`TURN provider answered ${response.status}`);
    const json = await response.json();
    const given = Array.isArray(json.iceServers) ? json.iceServers : [json.iceServers];
    for (const server of given) {
      if (!server?.urls) continue;
      const urls = (Array.isArray(server.urls) ? server.urls : [server.urls])
        // Port 53 is blocked by browsers and many networks; it only delays ICE.
        .filter((url) => !/:53(\?|$)/.test(url));
      if (urls.length) servers.push({ ...server, urls });
    }
  }
  return { iceServers: servers, ttl };
}
