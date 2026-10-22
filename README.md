# ZeroByte Relay

The relay server of ZeroByte: a mailbox for end-to-end encrypted envelopes
between two paired devices. It implements
[Relay Protocol v1](https://github.com/zerobyte-cloud/zerobyte-protocol/blob/master/relay-v1.md).
Devices seal every envelope with keys the relay never receives. The relay files
envelopes by mailbox, direction and sequence, and the reader deletes them once
it has collected them.

It runs in two places from the same protocol core:

- **Node**, on any server, with no dependencies. Storage is one SQLite file.
- **Cloudflare Workers**, with one SQLite-backed Durable Object per mailbox.

The same code runs the hosted relay at `relay.zerobyte.cloud`, where apps are registered
through [console.zerobyte.cloud](https://console.zerobyte.cloud). Or run your own.

## What the relay sees

| The relay sees | The relay never receives |
|---|---|
| The app id and a random 128-bit mailbox name | The content of any envelope |
| The SHA-256 of one access token per mailbox | The link key or any key derived from it |
| Envelope sizes, sequence numbers and times | Names, email addresses, device names |
| The IP address of a connection while it lasts | |
| When a signal frame passes, and its size | The content of a signal frame |
| | The APNs device token or FCM registration token, outside a request that presents the bearer |

The optional extensions below are off unless an app turns them on.

## Run it

Every request path starts with a registered app id: `/v1/<app>/mailbox/<id>`.
An app id is a UUIDv7. Generate one per app and pass the list in `RELAY_APPS`,
comma-separated. Each entry may carry a label: `<id>=notes`.

After the label, options separated by `;` give the app its own profile:

```text
RELAY_APPS=<id>=chat;push=com.example.chat;signal;ice;envelopes=1024;idle=90
```

| Option | Range | Meaning |
|---|---|---|
| `push=<topic>` | | Wake the reader through a push provider. For APNs the topic is the app's bundle id; FCM ignores it. Needs the APNs or FCM secrets. |
| `signal` | | WebSocket rendezvous for a direct connection between the two devices |
| `ice` | | Hand out STUN/TURN servers. Needs the ICE settings. |
| `envelopes=N` | 16–4096 | Envelopes waiting per direction (default 64) |
| `mailbox=MiB` | 1–256 | Bytes waiting per mailbox (default 32) |
| `envelope=KiB` | 1–1024 | Plaintext per envelope (default 1024) |
| `idle=days` | 1–365 | Erase a mailbox after this long without a write (default 30) |

An entry with no options keeps the Relay Protocol v1 defaults, so existing
configurations behave as before. A bad option stops the relay at start-up.

```sh
git clone https://github.com/zerobyte-cloud/zerobyte-relay.git
cd zerobyte-relay
npm run app-id                     # prints a fresh UUIDv7
```

### Node

Node 22.13 or newer. No `npm install` is needed.

```sh
RELAY_APPS=<app id> RELAY_DATA=./data/relay.sqlite PORT=8080 npm start
```

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_APPS` | (required) | Registered app ids, comma-separated |
| `RELAY_DATA` | `./data/relay.sqlite` | SQLite file |
| `PORT`, `HOST` | `8080`, `0.0.0.0` | Where to listen |
| `APNS_TEAM_ID`, `APNS_KEY_ID` | | Apple team id and the id of an APNs auth key (`push`, APNs module) |
| `APNS_PRIVATE_KEY` or `APNS_PRIVATE_KEY_FILE` | | That key's `.p8`, as text or a path |
| `FCM_SERVICE_ACCOUNT` or `FCM_SERVICE_ACCOUNT_FILE` | | A Firebase service account's JSON key, as text or a path (`push`, FCM module) |
| `ICE_STUN_URLS` | | STUN URLs, comma-separated (`ice`) |
| `TURN_URLS`, `TURN_SECRET` | | coturn URLs and its `static-auth-secret` (`ice`) |
| `CF_TURN_KEY_ID`, `CF_TURN_API_TOKEN` | | Cloudflare Realtime TURN key (`ice`) |

The server speaks plain HTTP. Put TLS in front of it.

### Docker with automatic HTTPS

Point a DNS record at the host, then:

```sh
cd deploy
RELAY_DOMAIN=relay.example.com RELAY_APPS=<app id> docker compose up -d
```

Caddy obtains the certificate and writes no access log. The relay data lives in
the `relay-data` volume. To run the image without Caddy:

```sh
docker build -t zerobyte-relay .
docker run -p 8080:8080 -v relay-data:/data -e RELAY_APPS=<app id> zerobyte-relay
```

### Cloudflare Workers

Set `RELAY_APPS` in [`wrangler.toml`](wrangler.toml), and optionally a custom
domain under `routes`, then:

```sh
npm install
npx wrangler deploy
```

Idle watchers and signal sockets hibernate, so an open WebSocket costs nothing
while nothing arrives. Their `ping` is answered with `pong` by the runtime
without waking the mailbox.

For `push` and `ice`, store the keys as secrets:

```sh
npx wrangler secret put APNS_PRIVATE_KEY < AuthKey_ABC123DEFG.p8
npx wrangler secret put FCM_SERVICE_ACCOUNT < service-account.json
npx wrangler secret put TURN_SECRET          # or CF_TURN_API_TOKEN
```

Put `APNS_TEAM_ID`, `APNS_KEY_ID`, `ICE_STUN_URLS`, `TURN_URLS` and
`CF_TURN_KEY_ID` under `[vars]`. APNs needs HTTP/2, which deployed Workers
negotiate but `wrangler dev` does not: test real pushes on a deployed relay or
on Node.

### Point the SDKs at it

Every SDK takes a base URL. For your relay it is
`https://relay.example.com/v1/`; the SDK appends the app id.

### Apps signed up at run time

`RELAY_APPS` is fixed at deploy time. A relay that lets people register apps
through a console also binds a KV namespace as `REGISTRY` and the secret
`REGISTRY_KEY` (32 random bytes, base64). The console writes `apps:index`, the
list of app ids, and one `app:<id>` entry per app:

```json
{"name": "notes", "options": "push=com.example.notes;signal", "status": "active",
 "secrets": {"iv": "…", "data": "…"}}
```

`options` is written as in `RELAY_APPS`. `status` is `active`, or `suspended`
to refuse the app's writes with `402 payment_required` while reads, prunes and
erasing still work. `secrets` holds the app's own APNs key or FCM service
account, sealed with AES-256-GCM under `REGISTRY_KEY` with the app id as
additional data; the relay sends that app's pushes with them. Each isolate reads
the index and an entry at most once a minute, so an unknown app id costs no KV
read and a change reaches the relay within about two minutes. The relay never
writes to the namespace. See [`src/registry.js`](src/registry.js).

## What it keeps

| Kept | Where | How long |
|---|---|---|
| SHA-256 of the mailbox's access token | The mailbox | Until the mailbox is erased |
| Unread envelopes, their sequences, total bytes | The mailbox | Until the reader prunes them, or 30 to 31 days without a write |
| A push registration per direction, sealed (below) | The mailbox | Until it is replaced or deleted, APNs or FCM reports it dead, or the mailbox is erased |
| Rate-limit counters | Memory only | While the mailbox is in use |
| Request logs | Nowhere | |

The Node server prints one line at start and never logs a request. SQLite runs
with `secure_delete`, so pruned ciphertext is overwritten on disk. The Cloudflare
configuration turns Workers Logs and traces off.

`relay.zerobyte.cloud` (`wrangler.hosted.toml`) also counts requests and bytes
per app as load statistics, in Cloudflare Analytics Engine. Each data point holds the app
id, the operation, the status class and the byte count: no mailbox name, token,
sequence or IP address. A relay you run yourself counts nothing, because the
counter only runs when a `USAGE` binding exists.

## Extensions

All three are optional and per app. A path an app has not enabled answers 404.

### Push

The reader registers its device once per direction:

```http
PUT /v1/<app>/mailbox/<id>/<p2c|c2p>/push
Authorization: Bearer <token>

{"service":"apns","token":"<hex>","environment":"production","tag":"<1-64 chars>","alert":"New message"}
{"service":"fcm","token":"<FCM registration token>","tag":"<1-64 chars>","alert":"New message"}
```

A writer that wants the reader woken adds `X-Relay-Notify: alert` (a visible
notification with `mutable-content`, for a Notification Service Extension) or
`X-Relay-Notify: silent` (a background push) to its `PUT`. The push carries
only `{"zerobyte":{"tag":"…"}}`: no mailbox name, sequence or content. The app
looks the tag up locally, fetches and decrypts. The relay sends no push while
the reader has a watcher open that sent `ping` in the last 45 seconds.

On Android every FCM message is data-only, so the app's
`FirebaseMessagingService` always receives it and draws the notification
itself: `data` holds `zerobyte_tag`, `zerobyte_notify` (`alert` or `silent`)
and, for an alert, `zerobyte_alert`, the registered text. Alerts go at high
priority, silent pushes at normal.

The registration is stored encrypted with AES-256-GCM under a key derived from
the mailbox's bearer token, which the relay keeps only as a SHA-256. A copy of
the database therefore reveals no device tokens and cannot link two mailboxes
of one device. `DELETE …/push` removes it; APNs answering 410, or FCM
answering `UNREGISTERED`, removes it too.

The relay core knows no push service. `service`, `tag` and `alert` are generic;
the other fields belong to a provider module that checks and sends them. Two
are shipped, [`src/apns/`](src/apns/) and [`src/fcm/`](src/fcm/), each
configured only when its settings are present. Another service (UnifiedPush, an
app's own gateway)
is a module with the same four members (`service`, `parse`, `send`, `close`),
passed to `createRelayServer({ push })` or `env.PUSH`. A registration for a
service the relay has no module for is kept, so devices may register before the
operator adds one.

### Signal

`GET /v1/<app>/mailbox/<id>/signal/<primary|companion>`, upgraded to a
WebSocket with the same subprotocols as watch. Binary frames of up to 64 KiB
are forwarded to the other side unread; the devices seal them. The relay sends
the text `peer 1` when both sides are connected and `peer 0` when the other
side leaves. A second connection for the same side replaces the first (close
4000). Text other than `ping` closes the socket with 1003. Use it to exchange
WebRTC/ICE offers, then talk directly.

### ICE

`GET /v1/<app>/mailbox/<id>/ice` answers `{"iceServers":[…],"ttl":3600}` with
short-lived TURN credentials: coturn REST (`TURN_SECRET`) and/or Cloudflare
Realtime TURN. A TURN server relays the peer-to-peer traffic when a direct path
fails. It sees both IP addresses but only ciphertext.

### Rate limits

Each mailbox has token buckets in memory. A request over the limit gets
`429 rate_limited` with `Retry-After` in seconds.

| Bucket | Burst | Refill |
|---|---|---|
| Writes | 120 | 2/s |
| Reads, fetches, prunes | 240 | 4/s |
| WebSocket connects | 20 | 1 per 5 s |
| Signal frames per side | 400 | 50/s |
| Pushes per direction | 20 | 1 per 2 s |
| Push registrations | 10 | 1/min |
| ICE credentials | 6 | 1 per 30 s |

A confirmed claim (`PUT` with the same digest, 204) restarts the idle timer, so
an app can keep a quiet mailbox alive without writing to it.

## Limits

| Limit | Default | Per-app range |
|---|---|---|
| Envelope | 1 MiB of plaintext plus 38 bytes | 1 KiB to 1 MiB |
| Mailbox | 32 MiB, 64 envelopes per direction | 1 to 256 MiB, 16 to 4096 envelopes |
| One fetch | 16 envelopes | |
| Idle mailbox | Erased 30 to 31 days after the last write | 1 to 365 days (plus one) |
| Signal frame | 64 KiB | |

## Development

```sh
npm test
```

The tests use `node --test` and cover the protocol core, the Cloudflare adapter
and the Node server.

| Path | What it is |
|---|---|
| `src/core.js` | The whole protocol. It knows nothing about where it runs. |
| `src/cloudflare.js` | Worker entry point and the `Mailbox` Durable Object |
| `src/node/` | HTTP server, WebSocket and SQLite storage for Node |
| `src/apps.js` | Parsing of `RELAY_APPS`, app profiles and app id generation |
| `src/registry.js` | Apps signed up at run time, read from a KV namespace |
| `src/rate.js` | Per-mailbox token buckets |
| `src/push.js` | Push registrations, sealed at rest, and the provider interface |
| `src/apns/` | The APNs provider: provider tokens, payloads, HTTP/2 delivery on Node |
| `src/fcm/` | The FCM provider: service account OAuth, data-only messages |
| `src/ice.js` | STUN/TURN credentials |
| `vectors/relay-v1.json` | Known-answer vectors, copied from [zerobyte-protocol](https://github.com/zerobyte-cloud/zerobyte-protocol/tree/master/spec) |

Never regenerate the vectors from the code under test.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately, not in a
public issue.

## Licence

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`), see
[`LICENSE`](LICENSE). If you run a modified relay as a network service, you
must offer its source code to its users. The SDKs are Apache-2.0, so apps that
talk to a relay are not affected by the AGPL.

Please don't present a relay you run yourself as `zerobyte.cloud`.

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. relay.zerobyte.cloud runs the same code as a hosted service:
register an app at [console.zerobyte.cloud](https://console.zerobyte.cloud), or
run your own relay as described above.
