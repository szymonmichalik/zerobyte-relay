#!/usr/bin/env node
// Starts a self-hosted ZeroByte Relay.
//
//   RELAY_APPS   comma-separated registered app ids (required), see src/apps.js
//   RELAY_DATA   SQLite file (default ./data/relay.sqlite)
//   PORT, HOST   where to listen (default 8080 on 0.0.0.0)
//
//   zerobyte-relay app-id    prints a fresh app id

import { newAppID } from "../src/apps.js";
import { createRelayServer } from "../src/node/server.js";

if (process.argv[2] === "app-id") {
  console.log(newAppID());
  process.exit(0);
}

const apps = process.env.RELAY_APPS ?? "";
if (!apps.trim()) {
  console.error("RELAY_APPS is empty: register at least one app id (zerobyte-relay app-id).");
  process.exit(64);
}

const port = Number(process.env.PORT ?? 8080);
const host = process.env.HOST ?? "0.0.0.0";
const database = process.env.RELAY_DATA ?? "./data/relay.sqlite";

let server;
try {
  server = createRelayServer({ apps, database });
} catch (error) {
  console.error(error.message);
  process.exit(64);
}

server.listen(port, host, () => {
  const count = Object.keys(server.relay.apps).length;
  // The only line the relay prints: no request is ever logged.
  console.log(`ZeroByte Relay v1 on ${host}:${port}, ${count} app(s), data in ${database}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
