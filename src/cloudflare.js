// ZeroByte Relay on Cloudflare Workers: one SQLite-backed Durable Object per
// mailbox. This is how relay.zerobyte.cloud runs; anyone can deploy the same
// Worker to their own account (see README).
//
// Secrets (wrangler secret put), each optional:
//   APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY     push through APNs (src/apns/)
//   FCM_SERVICE_ACCOUNT                             push through FCM (src/fcm/)
//   TURN_SECRET, CF_TURN_API_TOKEN                  ice (apps with ice)
//   REGISTRY_KEY                                    opens app secrets in REGISTRY
// Variables: RELAY_APPS, and ICE_STUN_URLS, TURN_URLS, CF_TURN_KEY_ID for ice.
// Bindings: MAILBOX, and optionally USAGE (load statistics) and REGISTRY (a KV
// namespace of apps signed up through a console, src/registry.js).

import { handle, Mailbox as Core } from "./core.js";
import { appsFrom } from "./apps.js";
import { apnsFrom, fetchDeliver } from "./apns/index.js";
import { fcmFrom } from "./fcm/index.js";
import { pushProviders } from "./push.js";
import { iceFrom } from "./ice.js";
import { registryFrom } from "./registry.js";

let cached = null;
function settings(env) {
  // Tests pass ready objects; a deployment passes variables and secrets.
  const key = [
    env.RELAY_APPS,
    env.APNS_KEY_ID,
    env.FCM_SERVICE_ACCOUNT,
    env.CF_TURN_KEY_ID,
    env.TURN_URLS,
    env.ICE_STUN_URLS,
  ].join("|");
  if (!cached || cached.key !== key) {
    cached = {
      key,
      apps: appsFrom(env.RELAY_APPS),
      push: pushProviders(apnsFrom(env, fetchDeliver), fcmFrom(env)),
      ice: iceFrom(env),
    };
  }
  return {
    APPS: env.APPS ?? cached.apps,
    PUSH: "PUSH" in env ? env.PUSH : cached.push,
    ICE: "ICE" in env ? env.ICE : cached.ice,
  };
}

let registry = null;
/**
 * The settings for one request: an app from RELAY_APPS as configured, or one
 * from the registry with its own profile and, if it has them, push credentials.
 */
async function resolve(env, request) {
  const base = { ...env, ...settings(env) };
  if (!env.REGISTRY) return base;
  if (registry?.kv !== env.REGISTRY) {
    registry = { kv: env.REGISTRY, instance: registryFrom(env.REGISTRY, env.REGISTRY_KEY) };
  }
  const app = new URL(request.url).pathname.split("/")[2] ?? "";
  if (Object.hasOwn(base.APPS, app)) return base;
  const entry = await registry.instance.lookup(app);
  if (!entry) return base;
  return { ...base, APPS: { ...base.APPS, [app]: entry.profile }, PUSH: entry.push ?? base.PUSH };
}

export default {
  async fetch(request, env) {
    return handle(request, await resolve(env, request));
  },
};

export class Mailbox extends Core {
  constructor(state, env) {
    // Watchers and signal sockets keep themselves awake with "ping"; the
    // runtime answers "pong" without waking a hibernating object.
    try {
      // eslint-disable-next-line no-undef
      state.setWebSocketAutoResponse?.(new WebSocketRequestResponsePair("ping", "pong"));
    } catch {
      // Not available outside the Workers runtime.
    }
    const memory = {};
    super(
      {
        storage: state.storage,
        memory,
        sockets: (tag) => state.getWebSockets?.(tag) ?? [],
        tags: (socket) => state.getTags?.(socket) ?? [],
        lastPing: (socket) => state.getWebSocketAutoResponseTimestamp?.(socket)?.getTime() ?? null,
        waitUntil: (promise) => state.waitUntil?.(promise),
        upgrade: (_request, tag, protocol) => {
          // eslint-disable-next-line no-undef
          const pair = new WebSocketPair();
          const [client, server] = Object.values(pair);
          // Hibernating: an idle socket costs nothing and is woken by a write.
          state.acceptWebSocket(server, [tag]);
          const headers = protocol ? { "Sec-WebSocket-Protocol": protocol } : {};
          return {
            socket: server,
            response: new Response(null, { status: 101, webSocket: client, headers }),
          };
        },
      },
      { ...env, ...settings(env) },
    );
    this.deployment = env;
  }

  async fetch(request) {
    // A mailbox belongs to one app, so every request here resolves the same one.
    this.env = await resolve(this.deployment, request);
    return super.fetch(request);
  }
}
