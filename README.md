# WebSocket — realtime for the HKM Kernel

Solves `realtime.websocket`. An RFC 6455 server with per-channel authorised
subscriptions, fanned out across workers through the kernel's `PubSubPort`.

No WebSocket library. The framing is a header, a length in one of three forms
and a four-byte XOR — and the parts that are easy to get wrong are the parts a
library's defaults hide: whether an unmasked client frame is refused, whether a
non-minimal length is refused, and **whether `Origin` is checked at all**. The
last of those is your only defence against any page on the internet opening an
authenticated socket with a visitor's cookies, so it belongs in a repository you
can read next to the tests that pin it.

```bash
hkm plugins enable websocket
hkm cli realtime:status          # before a user meets the configuration
hkm cli realtime:serve           # the long-running server
```

## Three things to know before enabling it

**`WEBSOCKET_ORIGINS` is required with no default, so the boot fails until it is
set.** That is intended — see [the hijacking section](#origin-is-the-whole-defence).
An empty allowlist refuses every connection, and a permissive default would mean
every deployment that did not think about this shipped the vulnerability
invisibly, because the legitimate client works either way.

**Nothing is delivered until you bind a `ChannelAuthorizer`.** The default
refuses every subscription and logs why on each attempt. Also intended: the
alternative default broadcasts every event to every connected client, with a
demo that works perfectly and no error anywhere.

**Enabling the plugin does not start a server.** The HTTP surface is unchanged —
no stage, no route, no hook. `realtime:serve` is a separate long-running
process, and it needs a `PubSubPort` bound or it refuses to start.

## `Origin` is the whole defence

A WebSocket handshake **is not subject to the same-origin policy.** The browser
lets any page open a socket to any host, performs no CORS preflight, and
**attaches the target site's cookies**. So this, served from anywhere, runs in a
logged-in victim's browser:

```js
new WebSocket('wss://app.example.com/realtime')
```

…and the connection arrives authenticated as that user. Every subscription it
makes and every message it receives goes to the attacker's page. That is
Cross-Site WebSocket Hijacking, and the `Origin` header is the only place it can
be stopped: the browser sets it, a page cannot forge it, and nothing else in the
request distinguishes the attacker's page from the real one.

Matching is **exact and case-insensitive on the whole origin**, never a suffix
test. `str_ends_with($origin, 'example.com')` accepts every one of these, and
each is a different site under somebody else's control:

```
https://evil-app.example.com         https://app.example.com.attacker.net
https://app.example.com@evil.example http://app.example.com
```

A non-browser client sends no `Origin` at all. `WEBSOCKET_REQUIRE_ORIGIN=false`
permits that — correct for a mobile app, and wrong for a browser-only
deployment, where it removes the defence for any client that simply omits the
header. An attacker outside a browser has no victim's cookies to borrow, which
is the entire reason the header matters.

## Channels have no wildcards

Deliberately. A hierarchy is the obvious feature and the shortest path to an
authorisation bypass, because it inverts where the decision is made.

With exact names, every channel a connection holds was authorised individually:
the authoriser was asked about `documents.42` and said yes about `documents.42`.
With a pattern, it is asked about `documents.*` — a thing that does not exist and
has no owner — and must somehow answer for every document that might ever match,
including ones created after the subscription was granted. Almost every
implementation answers once, at subscribe time, and then delivers to the pattern
forever.

So a client wanting ten documents subscribes to ten channels and is checked ten
times. `WEBSOCKET_MAX_CHANNELS` is what makes that affordable.

## Why events go over a bus

An HTTP request is handled by one process. The realtime connections are spread
across all of them. A broadcaster that wrote to a local registry would reach only
the clients held by the worker that served this request:

> With four workers, a quarter of the subscribers see the update and three
> quarters never do, at random, with no error anywhere.

Under PHP-FPM it is worse — the HTTP process holds no realtime connections at
all, so nothing reaches anybody. The bug reproduces only under more than one
worker, which is to say never in development.

So `Broadcaster::publish()` puts the event on `PubSubPort` and every realtime
worker is subscribed. Bind Redis, NATS or MQTT; without one, `NullPubSub`
publishes nothing and **`realtime:serve` refuses to start** rather than hold
connections open and deliver nothing.

**One bus channel carries everything, with the targets in the payload.** The
natural design — one bus topic per application channel — needs either a pattern
subscription or a bus round trip per `subscribe` message. Patterns are where the
buses stop agreeing (`hkm.rt.*` vs `hkm.rt.>` vs `hkm/rt/#`), and putting that
into a kernel port would push one bus's syntax onto the others. The cost is
honest: every worker receives every event, including ones none of its clients
want. At tens of thousands of events a second, shard `WEBSOCKET_BUS_CHANNEL` by
event kind rather than reaching for patterns.

## Wiring it up

```php
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;

final class ProjectChannels implements ChannelAuthorizer
{
    public function allows(Identity $identity, Channel $channel): bool
    {
        return match ($channel->prefix()) {
            'account'   => $channel->identifier() === $identity->userId,
            'documents' => $this->documents->readableBy($identity, $channel->identifier()),
            default     => false,
        };
    }
}
```

It **must not throw** — it runs in the accept path, where an exception would drop
a connection that is behaving correctly. One that cannot reach its store should
return false; refusing on an outage is the safe direction and the server logs it.

It is consulted **once per channel per subscription, not per message** — a store
round trip in front of every delivery would not survive. To make a revocation
take effect at once, call `RealtimeServer::revoke($channel)` rather than waiting
for a reconnect.

## The client protocol

```js
const ws = new WebSocket('wss://app.example.com/realtime', 'hkm.realtime.v1');

ws.onopen = () => ws.send(JSON.stringify({
    type: 'subscribe', channels: ['documents.42', 'account.me'],
}));
```

| Sent | Received |
|---|---|
| | `{"type":"connected","protocol":…,"identity":{…}}` |
| `{"type":"subscribe","channels":[…]}` | `{"type":"subscribed","granted":[…],"denied":[…]}` |
| `{"type":"unsubscribe","channels":[…]}` | `{"type":"unsubscribed","channels":[…],"reason":"requested"}` |
| `{"type":"ping"}` | `{"type":"pong"}` |
| `{"type":"presence.join",…}` and friends | see [Presence](#presence--online-typing-viewing) |
| | `{"type":"event","channels":[…],"payload":{…}}` |
| *(anything malformed)* | `{"type":"error","message":…}` |

`granted` and `denied` are **both always present**. A client that believes it is
subscribed and is not waits forever for an event that was never going to arrive
— a silent partial success is worse than a flat refusal, which at least
surfaces.

`denied` says **which** channels, never **why**. Distinguishing "no such channel"
from "exists and is not yours" would make this socket an existence oracle for
every object in the application, probeable one name at a time by anyone who can
connect. The authoriser's reasoning goes to the log.

A `{"type":"ping"}` message exists because **browsers cannot send protocol ping
frames from JavaScript** — a JSON one is the only keepalive a web client has.
The server answers protocol pings too, echoing the payload exactly.

## Presence — online, typing, viewing

Who is on a channel, who is typing in it, and which record each person has
open. It rides on the channels you already authorise: **no second permission**.

```js
ws.send(JSON.stringify({type: 'presence.join', channel: 'documents.42'}));
// → {"type":"presence.members","channel":"documents.42",
//    "members":[{"userId":"ana","typing":false,"viewing":["invoices.7"]}, …]}

ws.send(JSON.stringify({type: 'presence.typing',  channel: 'documents.42', typing: true}));
ws.send(JSON.stringify({type: 'presence.viewing', channel: 'documents.42', target: 'invoices.7'}));
ws.send(JSON.stringify({type: 'presence.viewing', channel: 'documents.42', target: null}));
ws.send(JSON.stringify({type: 'presence.leave',   channel: 'documents.42'}));
ws.send(JSON.stringify({type: 'presence.members', channel: 'documents.42'}));   // re-read the list
```

Changes reach everyone on the channel as an ordinary `event` whose payload is:

```json
{"kind":"presence","action":"joined","channel":"documents.42","userId":"ana"}
{"kind":"presence","action":"left",  "channel":"documents.42","userId":"ana"}
{"kind":"presence","action":"typing","channel":"documents.42","userId":"ana","typing":true,"expiresIn":6}
{"kind":"presence","action":"viewing","channel":"documents.42","userId":"ana","targets":["invoices.7"]}
```

Three behaviours a client has to know:

- **A user, not a tab.** Two tabs are one user. `joined` fires for the first,
  `left` when the **last** closes, and `targets` is the set across all tabs.
- **Expire `typing` yourself.** `expiresIn` is seconds. The explicit
  `typing:false` after a lapse depends on the sweep and arrives late; the client
  timer does not. Send `typing:true` every ~2 s while the person types — only a
  *change* is announced.
- **You are told when you are not joined.** `typing`/`viewing` without a live
  join answer `error`, so a client whose entry lapsed knows to `presence.join`
  again. A live connection is renewed by the server, not by the client.

### Where the state lives, and why it is not in memory

Each channel's members are one value in the kernel's **`CachePort`**; changes are
announced on the **`PubSubPort`** you already bound. A map in a worker's memory is
correct for exactly one worker: with two, "is Ana online?" is answered for the
half of the connections that share a process with the asker. There is **no
in-memory fallback** — without a `CachePort`, presence is off and `realtime:serve`
says so at start.

Every change is a read-modify-write of one key under `CachePort::lock()` (the
cache cannot list keys, so a key per member is not an option). A lock timeout or
cache outage returns "unavailable" and is logged; **presence never throws** into
the message path.

### Expiry, and the one worker that sweeps

A member carries a lease (`WEBSOCKET_PRESENCE_TTL`, 45 s). Two mechanisms:

1. **Lazy.** A lapsed member is not returned by a read and is dropped by the next
   write, so the list is right even if nothing ever sweeps.
2. **The sweep**, so a channel nobody touches still announces that its last
   member left. A user whose worker was killed stays "online" to everyone else
   until it runs.

Each worker renews the leases of **its own** connections every `ttl/3`; nobody
else can, since only that process knows the socket is open. That is also what
makes a crashed worker's users expire: the dead process stops renewing.

**The sweep runs in worker 0 only** (`PresenceScheduler::start()`). Swoole
forks, and a timer started in every worker is N processes expiring everybody on
every tick. It is the same reason the kernel polls `shouldStop()` from worker 0
alone. A respawned worker 0 keeps its id and resumes; while it is down nothing is
wrong, only late. A second server on another host would also have a worker 0, so
the sweep takes a cache lock and a loser skips.

On a graceful stop the worker removes its own members in `workerStop` — the
kernel's SIGTERM trap and `ServerContract::stop()` never run under Swoole. A kill
skips that and the lease covers it.

### Privacy — presence is personal data

- A member is **a `userId`, whether they are typing, and the record ids they are
  viewing.** Never a name, email, role, connection id or node id.
- **Authorising a channel authorises seeing who is on it.** Everyone subscribed
  can see the list and the events. If that is too broad for a channel, put
  presence on a narrower one (`presence.documents.42`) with its own rule.
- Presence needs a **signed-in** connection and a **granted subscription**.
  Guests are refused. Revoking a channel (or unsubscribing) removes the member.
- `realtime:status` prints presence **settings only**. Nothing in the logs or
  status output lists who is online; log lines carry the channel name and an
  exception class, never a user id.
- **Channel names are global.** Presence is keyed by channel name exactly like
  delivery is, so put the tenant in the name (`tenant.7.documents.42`) if two
  tenants can reach the same server.
- A connection can change typing/viewing about once a second; a channel holds at
  most `WEBSOCKET_PRESENCE_MAX_MEMBERS` connections.

Presence is implemented in the PHP/Swoole server (`realtime:serve`). **The Go
edge in `edge/` does not speak it.**

### Connection identity (new in 1.1.0)

`realtime:serve` now asks a bound `ConnectionIdentifier` who the socket is, from
the upgrade request (`cookie`, `authorization`, `?token=`, …). With none bound
every socket is a guest, public channels work, and presence is refused — there
is nobody to show. Before 1.1.0 this was a stub that always returned a guest.

## What the frame codec refuses, and why

A round-trip test proves the codec agrees with itself, which was never in doubt.
These are the frames a conforming peer never sends:

| Refused | Close | Why it matters |
|---|---|---|
| an unmasked client frame | 1002 | masking stops a sandboxed script authoring the bytes on the wire — the cache-poisoning-proxy attack that made it mandatory |
| a non-minimal length | 1002 | three encodings of one number is three chances for a proxy and a server to disagree where a frame ends. Same class as HTTP request smuggling |
| a 64-bit length with the high bit set | 1002 | `unpack('J')` returns a **negative** int, and a negative length makes every bounds check pass |
| a set RSV bit | 1002 | RSV1 is `permessage-deflate`; ignoring it means every length and UTF-8 check runs on compressed bytes |
| a fragmented or >125-byte control frame | 1002 | a ping must be deliverable *between* fragments; without the cap an unauthenticated client picks the allocation size |
| a frame over the limit | **1009** | not 1002 — the code is what stops a client reconnecting forever over one oversized message |
| invalid UTF-8 in a text message | 1007 | checked on the **whole** message: a character may legally straddle a fragment boundary |

The response **never** echoes `Sec-WebSocket-Extensions`. Echoing
`permessage-deflate` without implementing it is catastrophic rather than untidy:
the client would compress every payload and set RSV1, and this server reads
neither.

## Config

| Env | Default | |
|---|---|---|
| `WEBSOCKET_ORIGINS` | **required** | comma-separated exact origins |
| `WEBSOCKET_REQUIRE_ORIGIN` | `true` | false only for non-browser clients |
| `WEBSOCKET_HOST` / `_PORT` | `127.0.0.1` / `9503` | front it with a TLS terminator |
| `WEBSOCKET_PATH` | `/realtime` | the upgrade path; anything else is 404 |
| `WEBSOCKET_WORKERS` | `2` | |
| `WEBSOCKET_BUS_CHANNEL` | `hkm.rt.events` | |
| `WEBSOCKET_MAX_CONNECTIONS` | `10000` | per worker; a full worker answers 1013 |
| `WEBSOCKET_MAX_CHANNELS` | `64` | per connection |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `8388608` | |
| `WEBSOCKET_IDLE_TIMEOUT` | `120` | seconds |
| `WEBSOCKET_PRESENCE` | `true` | off disables the `presence.*` messages; needs a `CachePort` |
| `WEBSOCKET_PRESENCE_TTL` | `45` | seconds a connection stays listed without renewal (min 9) |
| `WEBSOCKET_PRESENCE_TYPING_TTL` | `6` | seconds a typing indicator lasts (never above the TTL) |
| `WEBSOCKET_PRESENCE_SWEEP_INTERVAL` | `10` | seconds between sweeps, **worker 0 only** |
| `WEBSOCKET_PRESENCE_MAX_MEMBERS` | `500` | connections listed per channel |

Every misconfiguration here produces the **same symptom — nothing arrives** —
which is why `realtime:status` names the five distinct causes separately and
says which ones it cannot check from outside the server.

## Tests

291 tests. `phpunit.xml` now boots through `tests/bootstrap.php`, which finds the
kernel the way the sibling plugins do (`HKM_KERNEL_PATH`, then `vendor/`, then
`../../../PHP`); it used to name a `vendor/autoload.php` that a bare checkout
does not have.

What makes them worth something:

**The RFC's own worked example.** §1.3 publishes one key and its expected
`Sec-WebSocket-Accept`, and the suite reproduces it. That comes from outside this
codebase, so a hash applied in the wrong order, a hex digest instead of a raw
one, or a mistyped GUID all fail it.

**One byte at a time.** The reader is fed a 70 KB message a single byte per
`feed()`, the hardest schedule TCP can produce.

**The unmask is checked against a per-byte reference** for every length 0-300.

**Authorisation is asserted on what was sent, to which connection** — the
unauthorised connection must have **received nothing**.

**The indexes are fuzzed.** 4,000 random operations, asserting after each that the
two registry indexes still mirror each other.

**Presence: a second worker is a second service over one cache.** The service
holds no state, so two instances over one `FakeCache` are two workers, and the
only thing that can make them agree is the cache. The tests pin: a second worker
sees the first's members; a leave on one is seen by the other; a lapsed member
is dropped lazily and by the sweep; **a non-zero worker registers no sweep and,
when every timer it did register is fired against a stale entry, expires
nobody** — which fails if the `workerId === 0` guard is removed; two tabs are one
user; a lock timeout and a dead cache report "unavailable" instead of throwing;
and no event, log line or member list carries a connection id, node id or user id
where it should not. Each guard was broken one line at a time to confirm a test
notices (the outcomes are in the CHANGELOG).

### Verified, and not

**Run for real (OpenSwoole is not installed; Swoole 6.2.5 was, and the server
runs on either):** the actual `realtime:serve` code, 3 forked workers, a
file-backed bus and the kernel's cross-process `FileCache`, 12 clients spread
across the 3 worker pids. Observed: every client saw all 12 members; a `typing`
event raised on one worker reached the clients of the other two; a clean close
was announced to all; a `SIGKILL`ed worker's 5 users were announced `left` by the
survivors' sweep 7.8 s after the kill (lease 9 s) and dropped from the list; the
sweep lock was taken by **one pid only**, and after that pid was killed the
respawned worker 0 took over while the other workers still did not; a
`SIGTERM` produced a `left` for a connected user and left no process behind.

**Not verified:** a real browser; a real Redis/NATS/MQTT `PubSubPort` or Redis
`CachePort` (the run used a file bus and `FileCache`) — in particular whether an
adapter is safe to use for `publish()` from the same instance that is blocked in
`subscribe()`, and whether the Redis cache adapter is safe to use in coroutines;
more than 3 workers or more than one host; load (every presence change is a
blocking cache round trip in the worker's message path); that the SIGTERM `left`
came from `workerStop` rather than from Swoole's per-connection `close`; that
"worker 0" is the lowest pid (the guard is by worker id, the run only shows that
exactly one pid sweeps); and the Go edge, which has no presence.

## License

MIT.
