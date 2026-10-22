// ZeroByte Relay, self-hosted: the same protocol code as the Cloudflare Worker
// (core.js), on Node's own HTTP server and SQLite. No dependencies.
//
// It speaks plain HTTP; put TLS in front of it (Caddy, nginx, a load balancer).
// It writes no request log and keeps no usage counters.

import { createServer } from "node:http";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { DEFAULT_LIMITS, handle, Mailbox, reply } from "../core.js";
import { appsFrom } from "../apps.js";
import { Database } from "./storage.js";
import { handshake } from "./websocket.js";

const SWEEP_MILLISECONDS = 60_000;
const MEMORY_MILLISECONDS = 10 * 60_000;

/**
 * Builds a relay. `apps` is the RELAY_APPS text or a ready object; `database`
 * is a file path or ":memory:". `push` maps a service name to its provider
 * (push.js `pushProviders`, APNs from apns/index.js `apnsFrom`); `ice` comes
 * from ice.js `iceFrom`. Both may be null.
 */
export function createRelay({
  apps,
  database = ":memory:",
  now = () => Date.now(),
  push = null,
  ice = null,
} = {}) {
  const registered = typeof apps === "string" || apps === undefined ? appsFrom(apps) : apps;
  if (database !== ":memory:") mkdirSync(dirname(database), { recursive: true });
  const db = new Database(database);
  const watchers = new Map(); // mailbox name -> Set of { socket, tag }
  const memories = new Map(); // mailbox name -> rate buckets, while recently used
  const queues = new Map(); // mailbox name -> tail of its request chain
  const pending = new Set(); // work that outlives its response (pushes)
  const rawSockets = new WeakMap(); // Request -> net.Socket, for upgrades
  const env = { APPS: registered, PUSH: push, ICE: ice };

  // One request at a time per mailbox, as a Durable Object runs them.
  function serial(name, work) {
    const previous = queues.get(name) ?? Promise.resolve();
    const run = previous.then(work, work);
    const tail = run.catch(() => {});
    queues.set(name, tail);
    tail.then(() => {
      if (queues.get(name) === tail) queues.delete(name);
    });
    return run;
  }

  function entries(name) {
    return [...(watchers.get(name) ?? [])];
  }

  function mailbox(name) {
    if (!memories.has(name)) memories.set(name, {});
    const box = new Mailbox(
      {
        storage: db.storage(name),
        memory: memories.get(name),
        now,
        sockets: (tag) => entries(name).filter((w) => !tag || w.tag === tag).map((w) => w.socket),
        tags: (socket) => entries(name).filter((w) => w.socket === socket).map((w) => w.tag),
        lastPing: (socket) => socket.lastPing,
        waitUntil: (promise) => {
          pending.add(promise);
          promise.finally(() => pending.delete(promise));
        },
        upgrade: (request, tag, protocol) => {
          const raw = rawSockets.get(request);
          const socket = raw && handshake(raw, request, protocol);
          if (!socket) return { refused: reply(400) };
          const entry = { socket, tag };
          if (!watchers.has(name)) watchers.set(name, new Set());
          watchers.get(name).add(entry);
          socket.onmessage = (message) => mailbox(name).webSocketMessage(socket, message);
          socket.onclose = (code) => {
            // Tags stay readable during the close handler, as on Workers.
            try {
              mailbox(name).webSocketClose(socket, code);
            } finally {
              watchers.get(name)?.delete(entry);
              if (watchers.get(name)?.size === 0) watchers.delete(name);
            }
          };
          return {
            socket,
            response: new Response(null, { status: 200, headers: { "X-Upgraded": "1" } }),
          };
        },
      },
      env,
    );
    return box;
  }

  const front = {
    ...env,
    MAILBOX: {
      idFromName: (name) => name,
      get: (name) => ({ fetch: (request) => serial(name, () => mailbox(name).fetch(request)) }),
    },
  };

  async function sweep() {
    for (const name of db.due(now())) {
      await serial(name, async () => {
        const at = await db.storage(name).getAlarm();
        if (at !== null && at <= now()) await mailbox(name).alarm();
      });
    }
    for (const [name, memory] of memories) {
      if (!watchers.has(name) && !queues.has(name) && now() - (memory.at ?? 0) > MEMORY_MILLISECONDS) {
        memories.delete(name);
      }
    }
  }

  const largest = Math.max(
    DEFAULT_LIMITS.envelopeBytes,
    ...Object.values(registered).map((app) => app.limits?.envelopeBytes ?? 0),
  );

  return {
    apps: registered,
    database: db,
    maxBody: largest + 1,
    fetch: (request) => handle(request, front),
    rawSockets,
    sweep,
    /** Resolves when every push started so far has been sent. */
    settled: () => Promise.allSettled([...pending]),
    close: () => {
      for (const set of watchers.values()) for (const { socket } of set) socket.close(1001, "going away");
      for (const provider of Object.values(push ?? {})) provider.close?.();
      db.close();
    },
  };
}

function toRequest(incoming, origin) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (Array.isArray(value)) for (const v of value) headers.append(name, v);
    else if (value !== undefined) headers.set(name, value);
  }
  return new Request(new URL(incoming.url ?? "/", origin), {
    method: incoming.method,
    headers,
  });
}

async function readBody(incoming, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of incoming) {
    size += chunk.length;
    // Keep reading past the limit only far enough for core.js to answer 413.
    if (size > limit) {
      incoming.destroy();
      return Buffer.concat([...chunks, chunk]).subarray(0, limit);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function send(response, outgoing) {
  const headers = {};
  response.headers.forEach((value, name) => {
    headers[name] = value;
  });
  outgoing.writeHead(response.status, headers);
  const body = response.body ? Buffer.from(await response.arrayBuffer()) : null;
  outgoing.end(body);
}

/** An HTTP server for the relay; call `.listen(port, host)`. */
export function createRelayServer(options = {}) {
  const relay = createRelay(options);
  const origin = "http://relay.invalid";

  const server = createServer(async (incoming, outgoing) => {
    try {
      const base = toRequest(incoming, origin);
      const hasBody = incoming.method === "PUT";
      const request = hasBody
        ? new Request(base, { body: await readBody(incoming, relay.maxBody), duplex: "half" })
        : base;
      await send(await relay.fetch(request), outgoing);
    } catch {
      if (!outgoing.headersSent) await send(reply(400), outgoing).catch(() => {});
      else outgoing.destroy();
    }
  });

  server.on("upgrade", async (incoming, raw) => {
    raw.on("error", () => raw.destroy());
    try {
      const request = toRequest(incoming, origin);
      relay.rawSockets.set(request, raw);
      const response = await relay.fetch(request);
      if (response.headers.get("X-Upgraded") === "1") return;
      const body = Buffer.from(await response.arrayBuffer());
      const lines = [`HTTP/1.1 ${response.status} ${incoming.method === "GET" ? "Refused" : "Error"}`];
      response.headers.forEach((value, name) => lines.push(`${name}: ${value}`));
      lines.push(`content-length: ${body.length}`, "connection: close");
      raw.end(Buffer.concat([Buffer.from(lines.join("\r\n") + "\r\n\r\n"), body]));
    } catch {
      raw.destroy();
    }
  });

  const timer = setInterval(() => relay.sweep().catch(() => {}), SWEEP_MILLISECONDS);
  timer.unref();
  server.on("close", () => {
    clearInterval(timer);
    relay.close();
  });
  server.relay = relay;
  return server;
}
