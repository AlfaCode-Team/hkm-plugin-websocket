# Changelog

## 1.1.0 — 2026-11-11

### Added

- **Presence: online, typing, viewing.** `presence.join` / `.leave` / `.typing` /
  `.viewing` / `.members` client messages and `kind: presence` events
  (`joined`, `left`, `typing`, `viewing`). See the README.
- State lives in `CachePort` (one value per channel, changed under
  `CachePort::lock()`) and is announced over the existing `PubSubPort`, so it is
  shared by every worker. There is no in-memory fallback: without a `CachePort`
  presence is off.
- Members expire lazily on every read and write, and by a sweep that runs in
  **worker 0 only**. Every worker renews the leases of its own connections.
- `workerStop` removes a stopping worker's members (best effort; the lease
  covers a kill).
- Config: `WEBSOCKET_PRESENCE`, `WEBSOCKET_PRESENCE_TTL`,
  `WEBSOCKET_PRESENCE_TYPING_TTL`, `WEBSOCKET_PRESENCE_SWEEP_INTERVAL`,
  `WEBSOCKET_PRESENCE_MAX_MEMBERS`.
- `realtime:serve` resolves a socket's identity through a bound
  `ConnectionIdentifier` (cookie, authorization, `?token=`, remote IP, user
  agent, origin). With none bound, every socket is still a guest. Presence
  refuses guests.
- `API\Contracts\Ticker`, so which worker runs which timer is testable without a
  fork.

### Fixed

- **`realtime:serve` never registered a connection.** Swoole does not fire
  `onOpen` once an `onHandshake` handler is set, and the plugin registered an
  `open` handler anyway. Measured against a real server: no `connected` frame,
  and every `subscribe` answered "This connection is not registered." The unit
  tests never saw it because they call `RealtimeServer::onOpen()` directly.
  Registration now happens at the end of the handshake, deferred as Swoole's
  documentation prescribes.
- `phpunit.xml` pointed at a `vendor/autoload.php` a plugin checkout does not
  have; it now boots `tests/bootstrap.php`.

### Notes

- Presence is not implemented in the Go edge (`edge/`).
- `realtime:serve` is still a CLI command rather than a `servers[]` entry. That
  is how 1.0.0 shipped and was not changed here.
- Revert checks (a guard broken by a one-line edit, suite re-run): worker-0
  guard, close/unsubscribe/revoke/shutdown removing presence, the subscription
  gate, the guest refusal, lazy expiry on read and write, the channel lock, the
  member cap, the heartbeat re-add and lost-connection close-out, the node id in
  the member key, the typing throttle, the sweep lock, and change-only events
  were each noticed. Two were not at first: the sweep releasing a lock it never
  took (the shipped fake checks the owner — now covered by a lock that does not),
  and a `strval` on viewed targets that was dead code and was removed. The
  "typing needs a member" guard is noticed only through a PHP warning, not an
  assertion.
