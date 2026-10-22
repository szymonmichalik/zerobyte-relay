#!/usr/bin/env node
// Starts a self-hosted ZeroByte Relay.
//
//   RELAY_APPS   comma-separated registered app ids (required), see src/apps.js
//   RELAY_DATA   SQLite file (default ./data/relay.sqlite)
//   PORT, HOST   where to listen (default 8080 on 0.0.0.0)
//
// Optional, for apps that enable them in RELAY_APPS:
//   APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY (or APNS_PRIVATE_KEY_FILE)   push to Apple devices
//   FCM_SERVICE_ACCOUNT (or FCM_SERVICE_ACCOUNT_FILE)                       push to Android devices
//   ICE_STUN_URLS; TURN_URLS + TURN_SECRET; CF_TURN_KEY_ID + CF_TURN_API_TOKEN  ice
//
//   zerobyte-relay app-id    prints a fresh app id

import { readFileSync } from "node:fs";

import { newAppID } from "../src/apps.js";
import { iceFrom } from "../src/ice.js";
import { apnsFrom } from "../src/apns/index.js";
import { http2Deliver } from "../src/apns/node.js";
import { fcmFrom } from "../src/fcm/index.js";
import { pushProviders } from "../src/push.js";
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
  const secrets = { ...process.env };
  if (!secrets.APNS_PRIVATE_KEY && secrets.APNS_PRIVATE_KEY_FILE) {
    secrets.APNS_PRIVATE_KEY = readFileSync(secrets.APNS_PRIVATE_KEY_FILE, "utf8");
  }
  if (!secrets.FCM_SERVICE_ACCOUNT && secrets.FCM_SERVICE_ACCOUNT_FILE) {
    secrets.FCM_SERVICE_ACCOUNT = readFileSync(secrets.FCM_SERVICE_ACCOUNT_FILE, "utf8");
  }
  // Push providers: null for each one whose settings are absent.
  const push = pushProviders(apnsFrom(secrets, http2Deliver()), fcmFrom(secrets));
  const ice = iceFrom(secrets);
  server = createRelayServer({ apps, database, push, ice });
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
