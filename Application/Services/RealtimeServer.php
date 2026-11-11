<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\API\Contracts\Connections;
use Plugins\WebSocket\Domain\Channel;
use Plugins\WebSocket\Domain\CloseCode;
use Plugins\WebSocket\Domain\Frame;
use Plugins\WebSocket\Domain\Message;
use Plugins\WebSocket\Domain\Opcode;

/**
 * What the server DOES with a connection, independent of the transport.
 *
 * Three entry points — {@see self::onOpen()}, {@see self::onMessage()},
 * {@see self::onClose()} — and one outbound seam, {@see Connections}. No
 * sockets, no OpenSwoole, no event loop: those belong to the adapter that calls
 * this, which is what makes the authorisation decisions below testable without a
 * network.
 *
 * EVERY SUBSCRIPTION IS AUTHORISED INDIVIDUALLY, AND THE REPLY IS EXPLICIT
 * -----------------------------------------------------------------------
 * A `subscribe` message naming five channels produces five authoriser calls and
 * a reply that lists which were granted and which were not. Both halves matter:
 *
 *   - per channel, because that is the only granularity at which the
 *     authoriser can answer honestly. See {@see Channel} on why there are no
 *     wildcards;
 *   - explicitly, because a client that believes it is subscribed and is not
 *     waits forever for an event that was never going to arrive. A silent
 *     partial success is the worst outcome available here — worse than a flat
 *     refusal, which at least surfaces.
 *
 * THE REFUSAL DOES NOT SAY WHY
 * ----------------------------
 * `denied` lists the channel names and nothing else. Distinguishing "that
 * channel does not exist" from "it exists and is not yours" would make this
 * endpoint an existence oracle for every object in the application, probeable
 * one name at a time over a single socket by anyone who can connect. The
 * authoriser's reasoning goes to the log, where it has an operator rather than
 * an attacker.
 */
final class RealtimeServer
{
    /** The wire protocol version this server speaks, echoed on connect. */
    public const PROTOCOL = 'hkm.realtime.v1';

    /** Per worker: which of THIS worker's connections have joined presence. */
    private readonly LocalPresence $local;

    /**
     * Names this worker in a presence member key.
     *
     * A connection id is only unique within a worker (and is reused after a
     * close), so a shared presence entry keyed by it alone would collide across
     * workers and across restarts. Random per construction, i.e. per worker per
     * start: entries a dead worker leaves behind can never be mistaken for a new
     * worker's, and simply expire.
     */
    private readonly string $nodeId;

    public function __construct(
        private readonly ConnectionRegistry $registry,
        private readonly ChannelAuthorizer $authorizer,
        private readonly Connections $connections,
        private readonly ?LoggerPort $logger = null,
        /** Null disables the `presence.*` messages. */
        private readonly ?PresenceService $presence = null,
        string $nodeId = '',
    ) {
        $this->local  = new LocalPresence();
        $this->nodeId = $nodeId !== '' ? $nodeId : bin2hex(random_bytes(6));
    }

    /**
     * A connection has completed its handshake.
     *
     * The identity comes from the HANDSHAKE, not from a message: a client that
     * could announce who it was after connecting could announce anyone. See the
     * server adapter, which resolves it from the upgrade request's cookies or
     * bearer token before this is called.
     */
    public function onOpen(int $connectionId, Identity $identity): void
    {
        if (!$this->registry->open($connectionId, $identity)) {
            // At capacity. 1013 "try again later" rather than 1011 "server
            // error": it tells a client to back off and retry, where an error
            // code tells it something is broken and it may well retry at once.
            $this->connections->close(
                $connectionId,
                Frame::close(CloseCode::TryAgainLater, 'This server is at capacity.'),
            );

            $this->logger?->warning('websocket.connection.refused', [
                'reason'      => 'capacity',
                'connections' => $this->registry->connections(),
            ]);

            return;
        }

        $this->reply($connectionId, [
            'type'     => 'connected',
            'protocol' => self::PROTOCOL,
            // So a client knows whether it is talking as somebody. Deliberately
            // not the whole identity: roles and permissions are the server's
            // business, and echoing them hands a reconnaissance tool to anyone
            // who steals a session cookie.
            'identity' => [
                'authenticated' => !$identity->isGuest(),
                'userId'        => $identity->isGuest() ? null : $identity->userId,
            ],
        ]);
    }

    /** A decoded message arrived. Never throws; a bad message is answered. */
    public function onMessage(int $connectionId, Message $message): void
    {
        if ($message->isControl()) {
            $this->handleControl($connectionId, $message);

            return;
        }

        // Binary frames carry no protocol here. Answered rather than ignored:
        // a client sending protobuf to a JSON endpoint gets silence otherwise,
        // which is indistinguishable from a server that is not running.
        if (!$message->isText()) {
            $this->fail($connectionId, 'This server speaks JSON over text frames; a binary frame arrived.');

            return;
        }

        $payload = $message->json();

        if ($payload === null) {
            $this->fail($connectionId, 'The message is not a JSON object.');

            return;
        }

        $type = $payload['type'] ?? null;

        match (true) {
            $type === 'subscribe'   => $this->subscribe($connectionId, $payload),
            $type === 'unsubscribe' => $this->unsubscribe($connectionId, $payload),
            // A client-initiated application-level ping, distinct from a
            // protocol ping frame. Browsers cannot send protocol pings from
            // JavaScript at all, so a JSON one is the only keepalive a web
            // client has.
            $type === 'ping'        => $this->reply($connectionId, ['type' => 'pong']),
            \is_string($type) && str_starts_with($type, 'presence.')
                                    => $this->presenceMessage($connectionId, $type, $payload),
            default                 => $this->fail(
                $connectionId,
                'Unknown message type. Expected subscribe, unsubscribe, ping or a presence.* message.',
            ),
        };
    }

    public function onClose(int $connectionId): void
    {
        // Presence first, while the connection's channels are still known. A
        // closed socket that stayed listed would show a user as online until
        // their lease lapsed.
        $this->presence?->leaveEverywhere($this->memberKey($connectionId), $this->local->forget($connectionId));

        $this->registry->forget($connectionId);
    }

    /**
     * Deliver a published event to everyone subscribed to any of $channels.
     *
     * What the bus subscriber calls — see
     * {@see \Plugins\WebSocket\Infrastructure\Server\BusBridge}. The channels
     * come from trusted code rather than from a client, which is why fan-out
     * across several at once is allowed here and a wildcard subscription is
     * not.
     *
     * @param  list<Channel>        $channels
     * @param  array<string, mixed> $event
     * @return int                  connections written to
     */
    public function deliver(array $channels, array $event): int
    {
        if ($channels === []) {
            return 0;
        }

        $frame = Frame::text($this->encode([
            'type'     => 'event',
            'channels' => array_map(static fn (Channel $c): string => $c->name, $channels),
            'payload'  => $event,
        ]));

        $sent = 0;

        foreach ($this->registry->subscribersOfAny($channels) as $connectionId) {
            // A failed write means the client went away between the registry
            // read and the send, which is routine on any real network. Forget
            // it rather than retrying: the transport has already given up.
            if ($this->connections->send($connectionId, $frame)) {
                ++$sent;

                continue;
            }

            $this->registry->forget($connectionId);
        }

        return $sent;
    }

    /**
     * Drop a channel from everyone holding it and tell them.
     *
     * The mechanism behind a revoked permission. The authoriser is consulted
     * only at subscribe time — re-checking per message would put a store round
     * trip in front of every delivery — so this is what makes a revocation take
     * effect before the client happens to reconnect.
     */
    public function revoke(Channel $channel): int
    {
        $affected = $this->registry->revoke($channel);

        foreach ($affected as $connectionId) {
            // A revoked subscription takes the presence with it: someone no
            // longer allowed to see the channel must not stay listed on it, nor
            // keep an indicator on it.
            $this->presenceLeave($connectionId, $channel);

            $this->reply($connectionId, [
                'type'     => 'unsubscribed',
                'channels' => [$channel->name],
                'reason'   => 'revoked',
            ]);
        }

        return \count($affected);
    }

    // ── Message handlers ────────────────────────────────────────────────────

    /** @param array<string, mixed> $payload */
    private function subscribe(int $connectionId, array $payload): void
    {
        $identity = $this->registry->identityOf($connectionId);

        if ($identity === null) {
            // Unknown connection. Should be unreachable — onOpen runs first —
            // but a transport that delivers a message after a close would get
            // here, and creating a registry entry on the strength of a message
            // would mean a client could register itself with no handshake.
            $this->fail($connectionId, 'This connection is not registered.');

            return;
        }

        $requested = $this->channelNames($payload);

        if ($requested === []) {
            $this->fail($connectionId, 'A subscribe message needs a non-empty `channels` array.');

            return;
        }

        $granted = [];
        $denied  = [];

        foreach ($requested as $name) {
            $channel = Channel::parse($name);

            if ($channel === null) {
                $denied[] = $name;

                continue;
            }

            // The authorisation decision, once per channel. An authoriser that
            // throws despite its contract is treated as a refusal rather than
            // being allowed to drop a connection that is behaving correctly.
            try {
                $allowed = $this->authorizer->allows($identity, $channel);
            } catch (\Throwable $e) {
                $allowed = false;

                $this->logger?->error('websocket.authorizer.failed', [
                    'channel'   => $channel->name,
                    'exception' => $e::class,
                    'reason'    => $e->getMessage(),
                ]);
            }

            if (!$allowed || !$this->registry->subscribe($connectionId, $channel)) {
                $denied[] = $channel->name;

                continue;
            }

            $granted[] = $channel->name;
        }

        if ($denied !== []) {
            $this->logger?->info('websocket.subscribe.denied', [
                'userId'   => $identity->isGuest() ? null : $identity->userId,
                'channels' => $denied,
            ]);
        }

        // Both lists, always — including when one is empty. A client comparing
        // what it asked for with what it got needs the shape to be stable.
        $this->reply($connectionId, [
            'type'    => 'subscribed',
            'granted' => $granted,
            'denied'  => $denied,
        ]);
    }

    /** @param array<string, mixed> $payload */
    private function unsubscribe(int $connectionId, array $payload): void
    {
        $names   = $this->channelNames($payload);
        $removed = [];

        foreach ($names as $name) {
            $channel = Channel::parse($name);

            if ($channel === null) {
                continue;
            }

            $this->registry->unsubscribe($connectionId, $channel);
            $this->presenceLeave($connectionId, $channel);
            $removed[] = $channel->name;
        }

        $this->reply($connectionId, [
            'type'     => 'unsubscribed',
            'channels' => $removed,
            'reason'   => 'requested',
        ]);
    }

    private function handleControl(int $connectionId, Message $message): void
    {
        $frame = $message->frame;

        if ($frame === null) {
            return;
        }

        match ($frame->opcode) {
            // A pong carrying the ping's payload, as the specification
            // requires. Echoing something else, or nothing, makes a client that
            // matches payloads treat the connection as dead.
            Opcode::Ping  => $this->connections->send($connectionId, Frame::pong($frame->payload)),
            Opcode::Close => $this->connections->close($connectionId, Frame::close(CloseCode::Normal)),
            default       => null,   // a pong needs no answer
        };
    }

    // ── Presence ────────────────────────────────────────────────────────────

    /**
     * Renew the leases of this worker's connections. Called by a timer in EVERY
     * worker — see {@see PresenceScheduler}.
     *
     * A connection the transport no longer considers open is closed out here
     * instead of renewed: a client can vanish without the `close` event ever
     * arriving, and renewing its lease would keep a ghost online indefinitely.
     */
    public function presenceHeartbeat(): void
    {
        if ($this->presence === null) {
            return;
        }

        /** @var array<string, array<string, string>> $byChannel channel → member key → user id */
        $byChannel = [];

        foreach ($this->local->all() as $connectionId => $channels) {
            $identity = $this->registry->identityOf($connectionId);

            if ($identity === null || !$this->connections->isOpen($connectionId)) {
                $this->onClose($connectionId);

                continue;
            }

            foreach ($channels as $name) {
                $byChannel[$name][$this->memberKey($connectionId)] = $identity->userId;
            }
        }

        foreach ($byChannel as $name => $members) {
            $channel = Channel::parse((string) $name);

            if ($channel !== null) {
                $this->presence->heartbeat($channel, $members);
            }
        }
    }

    /**
     * This worker is stopping: take its members off every channel now rather
     * than leaving them to lapse.
     *
     * Wired to `workerStop`. Under Swoole the kernel's SIGTERM trap never fires
     * and `ServerContract::stop()` is never called, so this handler is the only
     * place a worker gets to say goodbye. It is best effort — a SIGKILL or a
     * crash skips it — and the lease TTL is what covers those.
     */
    public function presenceShutdown(): void
    {
        if ($this->presence === null) {
            return;
        }

        foreach (array_keys($this->local->all()) as $connectionId) {
            $this->presence->leaveEverywhere($this->memberKey($connectionId), $this->local->forget($connectionId));
        }
    }

    /** Joined presence connections held by THIS worker — a count, never who. */
    public function presenceConnections(): int
    {
        return $this->local->connections();
    }

    /** @param array<string, mixed> $payload */
    private function presenceMessage(int $connectionId, string $type, array $payload): void
    {
        if ($this->presence === null) {
            $this->fail($connectionId, 'Presence is not enabled on this server.');

            return;
        }

        $identity = $this->registry->identityOf($connectionId);

        if ($identity === null) {
            $this->fail($connectionId, 'This connection is not registered.');

            return;
        }

        if ($identity->isGuest()) {
            // There is nobody to show. A guest in a presence list would be an
            // anonymous entry that tells everyone else a stranger is watching.
            $this->fail($connectionId, 'Presence needs a signed-in connection.');

            return;
        }

        $rawChannel = $payload['channel'] ?? null;
        $channel    = \is_string($rawChannel) ? Channel::parse($rawChannel) : null;

        if ($channel === null) {
            $this->fail($connectionId, 'A presence message needs a valid `channel`.');

            return;
        }

        // The authorisation gate, and the only one: presence on a channel is
        // available to exactly the connections the authoriser already granted
        // that channel. There is no second permission to get out of step with it.
        if (!\in_array($channel->name, $this->registry->channelsOf($connectionId), true)) {
            $this->fail($connectionId, 'Subscribe to the channel before using presence on it.');

            return;
        }

        $key = $this->memberKey($connectionId);

        switch ($type) {
            case 'presence.join':
                if ($this->presence->join($channel, $key, $identity->userId) !== true) {
                    $this->fail($connectionId, 'Presence is unavailable for this channel right now.');

                    return;
                }

                $this->local->join($connectionId, $channel->name);
                $this->replyMembers($connectionId, $channel);

                return;

            case 'presence.members':
                $this->replyMembers($connectionId, $channel);

                return;

            case 'presence.leave':
                $this->presenceLeave($connectionId, $channel);
                $this->reply($connectionId, ['type' => 'presence.left', 'channel' => $channel->name]);

                return;

            case 'presence.typing':
            case 'presence.viewing':
                $this->presenceActivity($connectionId, $type, $channel, $key, $payload);

                return;

            default:
                $this->fail($connectionId, 'Unknown presence message.');
        }
    }

    /** @param array<string, mixed> $payload */
    private function presenceActivity(int $connectionId, string $type, Channel $channel, string $key, array $payload): void
    {
        if ($this->presence === null) {
            return;
        }

        if (!$this->local->has($connectionId, $channel->name)) {
            $this->fail($connectionId, 'Join presence on this channel first.');

            return;
        }

        if ($type === 'presence.typing') {
            $typing = $payload['typing'] ?? true;

            if (!\is_bool($typing)) {
                $this->fail($connectionId, '`typing` must be true or false.');

                return;
            }

            // Stopping is never throttled — an indicator that cannot be cleared
            // is worse than one that is chatty — only starting is.
            if ($typing && $this->local->tooSoon($connectionId, 'typing', $this->presence->now())) {
                return;
            }

            $ok = $this->presence->typing($channel, $key, $typing);
        } else {
            $raw    = $payload['target'] ?? null;
            $target = null;

            if ($raw !== null) {
                $target = \is_string($raw) ? Channel::parse($raw) : null;

                if ($target === null) {
                    $this->fail($connectionId, '`target` must be a short name such as invoices.42, or null.');

                    return;
                }
            }

            if ($target !== null && $this->local->tooSoon($connectionId, 'viewing', $this->presence->now())) {
                return;
            }

            $ok = $this->presence->viewing($channel, $key, $target);
        }

        if (!$ok) {
            // The member lapsed (or the store is down). The next heartbeat
            // re-adds a live connection; the client is told so it can re-join.
            $this->fail($connectionId, 'Join presence on this channel first.');
        }
    }

    private function presenceLeave(int $connectionId, Channel $channel): void
    {
        if ($this->presence === null || !$this->local->has($connectionId, $channel->name)) {
            return;
        }

        $this->local->leave($connectionId, $channel->name);
        $this->presence->leave($channel, $this->memberKey($connectionId));
    }

    private function replyMembers(int $connectionId, Channel $channel): void
    {
        $members = $this->presence?->members($channel);

        if ($members === null) {
            $this->fail($connectionId, 'Presence is unavailable for this channel right now.');

            return;
        }

        $this->reply($connectionId, ['type' => 'presence.members', 'channel' => $channel->name, 'members' => $members]);
    }

    private function memberKey(int $connectionId): string
    {
        return $this->nodeId . ':' . $connectionId;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * The `channels` member as a list of strings.
     *
     * Also accepts a single string, because `{"channels": "documents.42"}` is
     * what a client writes first and refusing it teaches nothing. Non-strings
     * inside the array are dropped here and surface as `denied` entries, so a
     * client sending `[null]` is told rather than silently given an empty
     * grant.
     *
     * @param  array<string, mixed> $payload
     * @return list<string>
     */
    private function channelNames(array $payload): array
    {
        /** @var mixed $raw */
        $raw = $payload['channels'] ?? null;

        if (\is_string($raw)) {
            return $raw === '' ? [] : [$raw];
        }

        if (!\is_array($raw)) {
            return [];
        }

        $names = [];

        // Capped. The cap in ConnectionRegistry bounds what is STORED; this one
        // bounds the authoriser calls a single message can provoke, which is
        // the more expensive half — each one may be a database round trip.
        foreach (\array_slice(array_values($raw), 0, 64) as $value) {
            if (\is_string($value) && $value !== '') {
                $names[] = $value;
            }
        }

        return $names;
    }

    /** @param array<string, mixed> $payload */
    private function reply(int $connectionId, array $payload): void
    {
        $this->connections->send($connectionId, Frame::text($this->encode($payload)));
    }

    private function fail(int $connectionId, string $message): void
    {
        // An error MESSAGE, not a close. A malformed message is usually a bug
        // in one call site of a client that is otherwise working, and dropping
        // the socket for it makes every other subscription on that connection
        // collateral damage.
        $this->reply($connectionId, ['type' => 'error', 'message' => $message]);
    }

    /** @param array<string, mixed> $payload */
    private function encode(array $payload): string
    {
        // JSON_UNESCAPED_* so what goes on the wire is what a reader of a
        // packet capture expects, and JSON_INVALID_UTF8_SUBSTITUTE so an
        // application that put a broken byte in an event payload gets a
        // replacement character rather than json_encode returning false and
        // this server sending the string "false" to every subscriber.
        return json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        ) ?: '{"type":"error","message":"The server could not encode this message."}';
    }
}
