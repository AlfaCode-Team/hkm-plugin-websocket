# hkm-realtime — the Go WebSocket edge

A thin, static binary that holds WebSocket connections and fans out events from
NATS. It contains **no authorization rule, no database, no session parser and no
knowledge of your domain** — every decision about who may see which channel is
asked of the PHP application over NATS request/reply.

That is the whole architectural point, and it is worth being blunt about: a Go
edge that re-implemented the authorizer would be a *second place* for a channel
to be considered readable, and the two would drift. So it asks.

```
browser ──ws──▶ hkm-realtime ──NATS request/reply──▶ hkm cli realtime:authorize
                      ▲                                   (your ChannelAuthorizer)
                      └──NATS subscribe── hkm.rt.events ◀── Broadcaster::publish()
```

## You probably do not need this

`hkm cli realtime:serve` — the PHP server on OpenSwoole — does the same job and
is the right answer for most deployments: one process, no second language, and
its authorizer runs **in-process with no round trip**. It is covered by 228
tests.

This exists for when connection *count* is the constraint. A goroutine is a few
kilobytes of stack, so one of these holds six figures of idle sockets on modest
memory where PHP would need many workers.

**Both speak the identical client protocol**, so swapping one for the other is a
deployment change and not a client change.

## Why Go

Not raw speed — `uWebSockets.js` holds connections about as cheaply, and the
real bottleneck is the NATS fan-out and the authorize round trip, which are the
same whatever this is written in.

It is **distribution**. The kernel's provisioner (`hkm cli daemon:install`)
installs "a pinned-digest static binary", which is exactly what `go build`
produces: one ~11 MB file, cross-compiled for darwin/linux × amd64/arm64 from
one machine, with a SHA-256 to pin. Production already runs one Go binary
(`nats-server`) through that same mechanism, so this adds nothing to install. A
Node build would need Node on every production host plus an `npm install` with a
native addon — a second runtime to patch, and a supply-chain surface of its own.

## Running it

```bash
export WEBSOCKET_ORIGINS=https://app.example.com
export NATS_URL=nats://127.0.0.1:4222
export NATS_USER=hkm NATS_PASS=…            # whatever daemon:install wrote to .env

./hkm-realtime
```

It reads **the same `WEBSOCKET_*` variables as the PHP server**, deliberately —
an operator swapping one for the other should not have to re-learn or re-declare
their configuration, and two sets of names means two places to change a limit
with the usual result that one of them is changed.

And the PHP side has to be answering:

```bash
hkm cli realtime:authorize      # supervise it, and run more than one
```

While that is down the edge's requests time out, **every subscription is
denied**, and clients connect and receive nothing. Request/reply load-balances
across every listener, so two or three is cheap insurance.

## It refuses to start in three states

Each one would otherwise be a server that looks healthy and delivers nothing —
the failure this whole design is arranged to prevent.

| | Why it refuses |
|---|---|
| `WEBSOCKET_ORIGINS` empty | every connection would be refused, so there is nothing to do |
| a wildcard in `WEBSOCKET_ORIGINS` | matching is exact; a wildcard accepts `app.example.com.attacker.net` |
| NATS unreachable | no events to deliver and no authorizer to ask |

## `Origin` is the whole defence

A WebSocket handshake **is not subject to the same-origin policy**. The browser
lets any page open a socket to any host, performs no CORS preflight, and
**attaches the target site's cookies**. So this, served from anywhere, runs in a
logged-in victim's browser and arrives authenticated as them:

```js
new WebSocket('wss://app.example.com/realtime')
```

Matching is exact and case-insensitive on the **whole** origin. Each of these is
a different site under somebody else's control, and a suffix or wildcard test
accepts all of them:

```text
https://evil-app.example.com          https://app.example.com.attacker.net
https://app.example.com@evil.test     http://app.example.com
https://app.example.com:8443
```

The scheme and port are part of an origin, which is why the last two are in the
list. The refusal is a 403 **before** the upgrade and its body does not name the
allowlist — telling a rejected caller which origin would work hands a
non-browser client the exact string to send.

`WEBSOCKET_REQUIRE_ORIGIN=false` accepts a connection with *no* Origin header:
correct for a native client, which must then authenticate by token, and wrong
for a browser-only deployment. A typo in that variable resolves to `false`,
matching the PHP helper — so the server logs a warning about it at startup
rather than assuming somebody noticed.

## What it does with a slow client

Every delivery goes through a per-connection buffered channel, never a direct
socket write. When a buffer fills, **that connection is dropped** rather than
waited for.

The alternative is worse in a way that is easy to miss: blocking on a full
buffer holds the fan-out goroutine, so one client that stopped reading stops
delivery for *every other client on the edge*. The count is on `/statsz` as
`droppedSlowConsumers`, and a rising number means the application publishes
faster than clients read.

## Health

A **separate loopback listener**, because the WebSocket port is the one a
reverse proxy publishes to the internet and connection counts plus channel
names describe your event surface to anyone who can read them.

```bash
curl 127.0.0.1:9504/healthz    # ok
curl 127.0.0.1:9504/statsz     # {"version":…,"connections":…,"channels":…,"droppedSlowConsumers":…}
```

## Config

| Env | Default | |
|---|---|---|
| `WEBSOCKET_ORIGINS` | **required** | comma-separated exact origins; no wildcards |
| `WEBSOCKET_REQUIRE_ORIGIN` | `true` | false only for non-browser clients |
| `WEBSOCKET_LISTEN` | `127.0.0.1:9503` | front it with a TLS terminator |
| `WEBSOCKET_PATH` | `/realtime` | anything else is 404 |
| `WEBSOCKET_HEALTH_LISTEN` | `127.0.0.1:9504` | empty disables it |
| `WEBSOCKET_BUS_CHANNEL` | `hkm.rt.events` | must match the Broadcaster |
| `WEBSOCKET_AUTH_SUBJECT` | `hkm.rt.authorize` | must match `realtime:authorize` |
| `WEBSOCKET_MAX_CONNECTIONS` | `10000` | at the cap, new clients get 1013 Try Again Later |
| `WEBSOCKET_MAX_CHANNELS` | `64` | per connection |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `8388608` | inbound read limit |
| `WEBSOCKET_SEND_BUFFER` | `64` | how far a client may fall behind before it is dropped |
| `WEBSOCKET_IDLE_TIMEOUT` | `120` | seconds of silence before a connection is closed |
| `WEBSOCKET_AUTHORIZE_TIMEOUT` | `2` | seconds; on timeout every requested channel is denied |
| `NATS_URL` / `NATS_USER` / `NATS_PASS` / `NATS_TOKEN` | — | same names the NATS plugin uses |

## Building

```bash
go test -race ./...
go build -ldflags "-X main.version=1.0.0" -o hkm-realtime ./cmd/hkm-realtime

# Cross-compile the four platforms the daemon mechanism pins:
for p in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  GOOS=${p%/*} GOARCH=${p#*/} go build -ldflags "-X main.version=1.0.0" \
    -o "dist/hkm-realtime-${p%/*}-${p#*/}" ./cmd/hkm-realtime
done
```

## Tests

`go test -race ./...` — and the race detector matters here, because this is a
concurrent server and a data race is precisely the bug that only shows under
load.

**The shared channel vectors are the most interesting thing in the suite.**
There are two implementations of one rule set — `Plugins\WebSocket\Domain\Channel`
in PHP and `internal/channel` here. The duplication is deliberate: the edge must
refuse a malformed name *before* spending a round trip asking PHP about it,
because otherwise an unauthenticated client decides how much work the
application does, which is a denial-of-service primitive.

Deliberate or not, two implementations of a security rule drift — and silently,
because the stricter one refuses what the other allows and whichever side a
deployment runs decides what is reachable. So both suites read
`../shared/channel-vectors.json`. Changing one implementation and not the other
fails on one of them; that was verified by removing `:` from the Go charset and
watching the Go suite fail on a vector PHP accepts.

Other tests worth their keep:

- **Every hijacking vector** above, asserted refused, including the scheme and
  port cases people forget.
- **A real handshake** against `httptest` with a real client, so the
  subprotocol negotiation, the framing and the close codes are the library's
  actual behaviour rather than an assumption about it. Only the *authorizer* is
  faked — which is the point, since the real one is PHP.
- **`granted` and `denied` are asserted on the RAW JSON**, because the bug being
  prevented is Go-specific: a nil slice marshals to `null`, and `denied.length`
  on null throws in a browser.
- **A failed authorizer denies everything.** The convenient direction is so
  obviously the other one that it needs a test: an edge that granted on error
  would hand out every requested channel the moment PHP stopped answering —
  which is exactly when nobody is watching.
- **The edge intersects the authorizer's answer with the request.** A responder
  is trusted to decide, not trusted to be well-formed; a channel it "granted"
  that the client never asked for would subscribe the connection to something
  out of thin air. This test is why that guard lives in the *server* and not in
  the NATS client — it must hold for every `Authorizer` implementation.
- **The registry indexes are fuzzed** over 4,000 random operations, because an
  id left in the fan-out index after a socket closed is invisible until the
  transport *reuses* that id — at which point a new client inherits the previous
  occupant's subscriptions.
- **A slow consumer is dropped and the healthy one survives**, with the indexes
  still consistent afterwards.
- **Shutdown closes with 1001 Going Away**, which is the difference on a deploy
  between clients reconnecting at once and waiting out a backoff on a TCP reset.
  Finding this took a real bug: the drain flag was only checked *between* reads,
  so a loop blocked in `conn.Read` noticed a shutdown up to `IdleTimeout` late.

### What is not tested

- **No real browser.** Chrome accepting this handshake is a claim about Chrome.
- **No real NATS in the Go suite.** The authorizer and the bus are exercised
  through their interfaces; `internal/authz` (the NATS client) and
  `cmd/hkm-realtime` (wiring and signals) have no test files. The startup
  refusals were checked by hand.
- **No load test.** "Holds six figures of connections" is an argument from
  goroutine stack size, not a measurement taken here.
