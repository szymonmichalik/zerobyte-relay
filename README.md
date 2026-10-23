# ZeroByte Relay

The relay server of ZeroByte: a mailbox for end-to-end encrypted envelopes
between two paired devices. It implements
[Relay Protocol v1](https://github.com/szymonmichalik/zerobyte-protocol/blob/master/relay-v1.md).
Devices seal every envelope with keys the relay never receives. The relay files
envelopes by mailbox, direction and sequence, and the reader deletes them once
it has collected them.

It runs in two places from the same protocol core:

- **Node**, on any server, with no dependencies. Storage is one SQLite file.
- **Cloudflare Workers**, with one SQLite-backed Durable Object per mailbox.

The same code runs `relay.zerobyte.cloud` for Derived, which isn't open to
other apps. To use ZeroByte in your app, run your own.

## What the relay sees

| The relay sees | The relay never receives |
|---|---|
| The app id and a random 128-bit mailbox name | The content of any envelope |
| The SHA-256 of one access token per mailbox | The link key or any key derived from it |
| Envelope sizes, sequence numbers and times | Names, email addresses, device names |
| The IP address of a connection while it lasts | |

## Run it

Every request path starts with a registered app id: `/v1/<app>/mailbox/<id>`.
An app id is a UUIDv7. Generate one per app and pass the list in `RELAY_APPS`,
comma-separated. Each entry may carry a label: `<id>=notes`.

```sh
git clone https://github.com/szymonmichalik/zerobyte-relay.git
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

Idle watchers hibernate, so an open WebSocket costs nothing while no envelope
arrives.

### Point the SDKs at it

Every SDK takes a base URL. For your relay it is
`https://relay.example.com/v1/`; the SDK appends the app id.

## What it keeps

| Kept | Where | How long |
|---|---|---|
| SHA-256 of the mailbox's access token | The mailbox | Until the mailbox is erased |
| Unread envelopes, their sequences, total bytes | The mailbox | Until the reader prunes them, or 30 days without a write |
| Request logs | Nowhere | |

The Node server prints one line at start and never logs a request. SQLite runs
with `secure_delete`, so pruned ciphertext is overwritten on disk. The Cloudflare
configuration turns Workers Logs and traces off.

`relay.zerobyte.cloud` (`wrangler.hosted.toml`) also counts requests and bytes
per app as load statistics, in Cloudflare Analytics Engine. Each data point holds the app
id, the operation, the status class and the byte count: no mailbox name, token,
sequence or IP address. A relay you run yourself counts nothing, because the
counter only runs when a `USAGE` binding exists.

## Limits

| Limit | Value |
|---|---|
| Envelope | 1 MiB of plaintext plus 38 bytes |
| Mailbox | 32 MiB, 64 envelopes per direction |
| One fetch | 16 envelopes |
| Idle mailbox | Erased 30 days after the last write |

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
| `src/apps.js` | Parsing of `RELAY_APPS` and app id generation |
| `vectors/relay-v1.json` | Known-answer vectors, copied from [zerobyte-protocol](https://github.com/szymonmichalik/zerobyte-protocol/tree/master/spec) |

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
and the SDKs. relay.zerobyte.cloud runs the same code for Derived and isn't
open to other apps. To use ZeroByte in your app, run your own relay: see
[zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay).
