// ZeroByte Relay on Cloudflare Workers: one SQLite-backed Durable Object per
// mailbox. This is how relay.zerobyte.cloud runs; anyone can deploy the same
// Worker to their own account (see README).

import { handle, Mailbox as Core } from "./core.js";
import { appsFrom } from "./apps.js";

let cached = null;
function apps(env) {
  // Tests pass a ready object; a deployment passes the RELAY_APPS variable.
  if (env.APPS) return env.APPS;
  if (!cached || cached.source !== env.RELAY_APPS) {
    cached = { source: env.RELAY_APPS, apps: appsFrom(env.RELAY_APPS) };
  }
  return cached.apps;
}

export default {
  async fetch(request, env) {
    return handle(request, { ...env, APPS: apps(env) });
  },
};

export class Mailbox extends Core {
  constructor(state, env) {
    super(
      {
        storage: state.storage,
        sockets: (tag) => state.getWebSockets?.(tag) ?? [],
        upgrade: (_request, tag, protocol) => {
          // eslint-disable-next-line no-undef
          const pair = new WebSocketPair();
          const [client, server] = Object.values(pair);
          // Hibernating: an idle watcher costs nothing and is woken by `put`.
          state.acceptWebSocket(server, [tag]);
          const headers = protocol ? { "Sec-WebSocket-Protocol": protocol } : {};
          return new Response(null, { status: 101, webSocket: client, headers });
        },
      },
      { ...env, APPS: apps(env) },
    );
  }
}
