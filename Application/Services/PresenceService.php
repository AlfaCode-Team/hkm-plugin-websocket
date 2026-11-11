<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\WebSocket\Domain\Channel;
use Plugins\WebSocket\Domain\Presence\PresenceMember;

/**
 * Who is online, typing and looking at what — shared by every worker.
 *
 * WHY THE STATE IS IN THE CACHE AND NOT IN THIS OBJECT
 * ----------------------------------------------------
 * {@see ConnectionRegistry} is per worker, correctly: a connection belongs to
 * the process that accepted it. Presence is the opposite. "Is Ana online?" is a
 * question about the whole server, and with two workers a map in process memory
 * answers it for the half of the connections that happen to share a process
 * with the asker. It is wrong the moment a second worker exists, and it is
 * wrong silently: the list is plausible, just short.
 *
 * So the truth is one entry per channel in a {@see CachePort}, and this class
 * holds nothing but its collaborators. Two instances over one cache ARE two
 * workers, which is how the tests simulate a second worker without a fork.
 *
 * ONE CHANNEL, ONE KEY, ONE LOCK
 * ------------------------------
 * A channel's members are a single cache value, so every change is a
 * read-modify-write — and two workers doing that concurrently lose one of the
 * updates (both read `{ana}`, one writes `{ana,bo}`, the other `{ana,cy}`).
 * Each change therefore runs under {@see CachePort::lock()}. The alternative, a
 * key per member, needs a way to LIST keys and {@see CachePort} has none.
 *
 * EVENTS ARE DERIVED FROM A DIFFERENCE, NOT FROM THE OPERATION
 * ------------------------------------------------------------
 * Members are connections; announcements are about users. Closing one of a
 * user's two tabs removes a member and must announce nothing. So every change
 * snapshots the users before and after and announces what DIFFERS: appeared →
 * `joined`, gone → `left`, typing flipped → `typing`, the set of records they
 * are viewing changed → `viewing`. It is also what makes expiry announce
 * itself with no extra code: a member that lapses is just a difference.
 *
 * Events are published AFTER the lock is released, the same discipline as
 * integration events after a commit — a slow bus must not hold the channel's
 * lock, and an event must never describe a state that did not get stored.
 *
 * EXPIRY IS TWO MECHANISMS, AND ONLY ONE OF THEM IS A TIMER
 * --------------------------------------------------------
 *  - **Lazily, on every change and every read.** A member whose `expiresAt` has
 *    passed is not returned and is dropped by the next write. Correctness does
 *    not depend on any timer running: a deployment whose sweeper is down still
 *    reports the right list.
 *  - **By {@see self::sweep()}**, which exists so a channel nobody touches still
 *    announces that its last member left. Without it a user whose worker was
 *    killed stays "online" in every other client until somebody happens to act
 *    on that channel. Run it from ONE worker — see {@see PresenceScheduler}.
 *
 * WHAT IS EXPOSED, AND TO WHOM
 * ----------------------------------------------
 * A member is a `userId`, whether they are typing, and the record ids they are
 * viewing. Never an email, a name, roles, a connection id or a node id. The
 * caller ({@see RealtimeServer}) only hands this out to a connection already
 * authorised on the channel, so authorising a channel authorises seeing who is
 * on it. Nothing in here may be written to a log line or a status dump.
 *
 * It NEVER throws. Presence is not worth a dropped connection or a failed
 * request: a lock timeout or a cache outage is logged and the operation reports
 * "unavailable".
 */
final class PresenceService
{
    private const PREFIX = 'hkm.rt.presence';

    public function __construct(
        private readonly CachePort $cache,
        private readonly ClockPort $clock,
        private readonly Broadcaster $broadcaster,
        private readonly PresenceSettings $settings = new PresenceSettings(),
        private readonly ?LoggerPort $logger = null,
    ) {}

    public function settings(): PresenceSettings
    {
        return $this->settings;
    }

    /** Epoch seconds from the injected clock — for callers that rate-limit on it. */
    public function now(): int
    {
        return $this->clock->timestamp();
    }

    /**
     * Register (or refresh) a connection on a channel.
     *
     * @return bool|null true = listed; false = refused because the channel's
     *                   list is full; null = the store was unavailable
     */
    public function join(Channel $channel, string $memberKey, string $userId): ?bool
    {
        $max = $this->settings->maxMembers;
        $ttl = $this->settings->ttl;

        $result = $this->mutate($channel, function (array $members, int $now) use ($memberKey, $userId, $max, $ttl): array {
            if (!isset($members[$memberKey]) && \count($members) >= $max) {
                return [$members, false];
            }

            $existing = $members[$memberKey] ?? null;

            $members[$memberKey] = $existing !== null && $existing->userId === $userId
                ? $existing->withExpiry($now + $ttl)
                : new PresenceMember($userId, $now + $ttl);

            return [$members, true];
        });

        return $result === null ? null : $result['accepted'];
    }

    /** Remove a connection. Announces `left` only if it was the user's last. */
    public function leave(Channel $channel, string $memberKey): bool
    {
        $result = $this->mutate($channel, static function (array $members) use ($memberKey): array {
            $had = isset($members[$memberKey]);
            unset($members[$memberKey]);

            return [$members, $had];
        });

        return $result !== null && $result['accepted'];
    }

    /**
     * Remove a connection from every channel it joined.
     *
     * What a closing connection calls. Per channel, because there is no index
     * from member to channels in the store and building one would make every
     * join a second write.
     *
     * @param list<string> $channels
     */
    public function leaveEverywhere(string $memberKey, array $channels): void
    {
        foreach ($channels as $name) {
            $channel = Channel::parse($name);

            if ($channel !== null) {
                $this->leave($channel, $memberKey);
            }
        }
    }

    /**
     * Extend the lease of a worker's own connections on one channel.
     *
     * A member that is MISSING is re-added rather than ignored: it expired
     * because this worker was slow, or the cache lost its keys, and the
     * connection is demonstrably still open — the caller holds it. Ignoring it
     * would leave a live user permanently invisible.
     *
     * @param array<string, string> $memberUsers member key → user id
     */
    public function heartbeat(Channel $channel, array $memberUsers): bool
    {
        if ($memberUsers === []) {
            return true;
        }

        $ttl = $this->settings->ttl;
        $max = $this->settings->maxMembers;

        $result = $this->mutate($channel, static function (array $members, int $now) use ($memberUsers, $ttl, $max): array {
            foreach ($memberUsers as $key => $userId) {
                if (isset($members[$key])) {
                    $members[$key] = $members[$key]->withExpiry($now + $ttl);
                } elseif (\count($members) < $max) {
                    $members[$key] = new PresenceMember($userId, $now + $ttl);
                }
            }

            return [$members, true];
        });

        return $result !== null;
    }

    /**
     * Set or clear the typing indicator.
     *
     * Only for a member that exists: typing is not a way to join. Announced on
     * a CHANGE only — a client re-sending "typing" every two seconds while the
     * user types must not become a bus event every two seconds.
     */
    public function typing(Channel $channel, string $memberKey, bool $typing): bool
    {
        $ttl       = $this->settings->ttl;
        $typingTtl = $this->settings->typingTtl;

        $result = $this->mutate($channel, static function (array $members, int $now) use ($memberKey, $typing, $ttl, $typingTtl): array {
            if (!isset($members[$memberKey])) {
                return [$members, false];
            }

            // Activity is also liveness, so the lease is extended with it.
            $members[$memberKey] = $members[$memberKey]
                ->withTypingUntil($typing ? $now + $typingTtl : 0)
                ->withExpiry($now + $ttl);

            return [$members, true];
        });

        return $result !== null && $result['accepted'];
    }

    /**
     * Set or clear the record this connection is looking at.
     *
     * $target is a {@see Channel}-shaped name (`invoices.42`), which bounds its
     * length and charset — it is client-chosen text that every other member of
     * the channel will receive.
     */
    public function viewing(Channel $channel, string $memberKey, ?Channel $target): bool
    {
        $ttl = $this->settings->ttl;

        $result = $this->mutate($channel, static function (array $members, int $now) use ($memberKey, $target, $ttl): array {
            if (!isset($members[$memberKey])) {
                return [$members, false];
            }

            $members[$memberKey] = $members[$memberKey]
                ->withViewing($target?->name)
                ->withExpiry($now + $ttl);

            return [$members, true];
        });

        return $result !== null && $result['accepted'];
    }

    /**
     * Who is on a channel now, one entry per USER.
     *
     * Read-only and expiry-aware: a lapsed member is simply absent, with no
     * write — so reading is cheap and takes no lock.
     *
     * @return list<array{userId: string, typing: bool, viewing: list<string>}>|null
     *         null when the store is unavailable, which a caller must not
     *         present as "nobody is here"
     */
    public function members(Channel $channel): ?array
    {
        try {
            $members = $this->load($this->key($channel));
        } catch (\Throwable $e) {
            $this->unavailable('members', $channel, $e);

            return null;
        }

        $now   = $this->clock->timestamp();
        $users = [];

        foreach ($members as $member) {
            if ($member->expired($now)) {
                continue;
            }

            $users[$member->userId] ??= ['userId' => $member->userId, 'typing' => false, 'viewing' => []];

            if ($member->typingUntil > $now) {
                $users[$member->userId]['typing'] = true;
            }

            if ($member->viewing !== null) {
                $users[$member->userId]['viewing'][$member->viewing] = $member->viewing;
            }
        }

        ksort($users);

        return array_values(array_map(static fn (array $user): array => [
            'userId'  => $user['userId'],
            'typing'  => $user['typing'],
            'viewing' => self::targets($user['viewing']),
        ], $users));
    }

    /**
     * Expire what has lapsed on every channel that has members, announcing it.
     *
     * **Run this from exactly one worker per server.** The expiry itself is
     * idempotent and lock-protected, so a second sweeper cannot corrupt a list —
     * but each extra one is another cache round trip per channel per interval
     * for no information, and they race to be the one that announces. See
     * {@see PresenceScheduler}, which is where the one-worker rule lives.
     *
     * @return int|null events announced (members who lapsed, typing that ended);
     *                  null when another sweeper (on another host) holds the lock
     */
    public function sweep(): ?int
    {
        $lock     = null;
        $acquired = false;

        try {
            // Inside the try: a cache that is down throws from lock() itself,
            // and "never throws" has to hold for the first call too.
            $lock = $this->cache->lock(self::PREFIX . ':sweep', $this->settings->sweepInterval);

            $acquired = $lock->acquire();

            if (!$acquired) {
                return null;
            }

            $events = 0;

            foreach (array_keys($this->index()) as $name) {
                $channel = Channel::parse((string) $name);

                if ($channel === null) {
                    continue;
                }

                // A change that changes nothing: the expiry is in mutate().
                $result = $this->mutate($channel, static fn (array $members): array => [$members, true]);
                $events += $result['events'] ?? 0;
            }

            return $events;
        } catch (\Throwable $e) {
            $this->logger?->warning('websocket.presence.sweep_failed', [
                'exception' => $e::class,
                'reason'    => $e->getMessage(),
            ]);

            return null;
        } finally {
            try {
                // Only a lock THIS call took: releasing one we failed to get
                // is at best a no-op and at worst frees another sweeper's.
                if ($acquired) {
                    $lock?->release();
                }
            } catch (\Throwable) {
                // The TTL frees it.
            }
        }
    }

    // ── The one write path ──────────────────────────────────────────────────

    /**
     * Read, expire, change, write — under the channel's lock — then announce.
     *
     * @param  \Closure(array<string, PresenceMember>, int): array{0: array<string, PresenceMember>, 1: bool} $change
     * @return array{accepted: bool, events: int}|null null = store unavailable
     */
    private function mutate(Channel $channel, \Closure $change): ?array
    {
        $key      = $this->key($channel);
        $accepted = false;
        $events   = [];

        try {
            $this->cache->lock($key . ':lock', 5)->block(1, function () use ($channel, $key, $change, &$accepted, &$events): void {
                $now    = $this->clock->timestamp();
                $stored = $this->load($key);
                $before = $this->users($stored);

                [$members, $accepted] = $change($this->expire($stored, $now), $now);

                $events = $this->diff($channel, $before, $this->users($members));

                $this->store($channel, $key, $stored, $members);
            });
        } catch (\Throwable $e) {
            // Includes LockTimeoutException: contention, not corruption.
            $this->unavailable('write', $channel, $e);

            return null;
        }

        foreach ($events as $event) {
            $this->broadcaster->publishTo($channel->name, $event);
        }

        return ['accepted' => $accepted, 'events' => \count($events)];
    }

    /**
     * Drop lapsed members and lapsed typing.
     *
     * @param  array<string, PresenceMember> $members
     * @return array<string, PresenceMember>
     */
    private function expire(array $members, int $now): array
    {
        foreach ($members as $key => $member) {
            if ($member->expired($now)) {
                unset($members[$key]);
            } elseif ($member->typingUntil > 0 && $member->typingUntil <= $now) {
                $members[$key] = $member->withTypingUntil(0);
            }
        }

        return $members;
    }

    /**
     * Per-user state, from the members AS STORED.
     *
     * Deliberately not time-evaluated: the "before" snapshot must still count a
     * lapsed member, or expiry would produce no difference and no `left`.
     *
     * @param  array<string, PresenceMember> $members
     * @return array<string, array{typing: bool, viewing: list<string>}>
     */
    private function users(array $members): array
    {
        $users = [];

        foreach ($members as $member) {
            $users[$member->userId] ??= ['typing' => false, 'viewing' => []];

            if ($member->typingUntil > 0) {
                $users[$member->userId]['typing'] = true;
            }

            if ($member->viewing !== null) {
                $users[$member->userId]['viewing'][$member->viewing] = $member->viewing;
            }
        }

        foreach ($users as $id => $user) {
            $users[$id]['viewing'] = self::targets($user['viewing']);
        }

        return $users;
    }

    /**
     * @param  array<string, array{typing: bool, viewing: list<string>}> $before
     * @param  array<string, array{typing: bool, viewing: list<string>}> $after
     * @return list<array<string, mixed>>
     */
    private function diff(Channel $channel, array $before, array $after): array
    {
        $events = [];
        $base   = static fn (string $action, string $userId): array => [
            'kind' => 'presence', 'action' => $action, 'channel' => $channel->name, 'userId' => $userId,
        ];

        foreach ($after as $userId => $state) {
            $userId = (string) $userId;

            if (!isset($before[$userId])) {
                $events[] = $base('joined', $userId);

                continue;
            }

            if ($before[$userId]['typing'] !== $state['typing']) {
                $events[] = $base('typing', $userId) + [
                    'typing'    => $state['typing'],
                    // So a client can expire the indicator itself. The explicit
                    // `typing: false` is cleanup that depends on a sweep; this
                    // does not.
                    'expiresIn' => $state['typing'] ? $this->settings->typingTtl : 0,
                ];
            }

            if ($before[$userId]['viewing'] !== $state['viewing']) {
                $events[] = $base('viewing', $userId) + ['targets' => $state['viewing']];
            }
        }

        foreach ($before as $userId => $_) {
            if (!isset($after[$userId])) {
                $events[] = $base('left', (string) $userId);
            }
        }

        return $events;
    }

    // ── Storage ─────────────────────────────────────────────────────────────

    /**
     * Persist the new member map, and keep the channel index in step.
     *
     * Skips the write when nothing changed, so a sweep over a healthy channel is
     * one read and no write.
     *
     * @param array<string, PresenceMember> $stored
     * @param array<string, PresenceMember> $members
     */
    private function store(Channel $channel, string $key, array $stored, array $members): void
    {
        if ($members === []) {
            if ($stored !== []) {
                $this->cache->delete($key);
            }

            $this->indexChange($channel, false);

            return;
        }

        if ($this->raw($members) !== $this->raw($stored)) {
            // Three leases: long enough that a heartbeat which is late does not
            // find the whole key gone, short enough that an abandoned channel
            // does not live in the cache forever.
            $this->cache->set($key, $this->raw($members), $this->settings->ttl * 3);
        }

        if ($stored === []) {
            $this->indexChange($channel, true);
        }
    }

    /**
     * Channels that have (or recently had) members.
     *
     * The sweep needs to know where to look, and {@see CachePort} cannot list
     * keys. A worker cannot be asked either — the one that knew may be the one
     * that died.
     *
     * @return array<string, int>
     */
    private function index(): array
    {
        $value = $this->cache->get(self::PREFIX . ':index');

        if (!\is_array($value)) {
            return [];
        }

        $clean = [];

        foreach ($value as $name => $_) {
            $clean[(string) $name] = 1;
        }

        return $clean;
    }

    private function indexChange(Channel $channel, bool $present): void
    {
        $indexKey = self::PREFIX . ':index';

        try {
            // Lock order is always channel → index, and nothing holds the index
            // lock while taking a channel's, so the two cannot deadlock.
            $this->cache->lock($indexKey . ':lock', 5)->block(1, function () use ($indexKey, $channel, $present): void {
                $index = $this->index();

                if ($present === isset($index[$channel->name])) {
                    return;
                }

                if ($present) {
                    $index[$channel->name] = 1;
                } else {
                    unset($index[$channel->name]);
                }

                $this->cache->set($indexKey, $index);
            });
        } catch (\Throwable $e) {
            // The channel still expires lazily and by TTL; it just will not be
            // swept, so its `left` event waits for the next change.
            $this->unavailable('index', $channel, $e);
        }
    }

    /** @return array<string, PresenceMember> */
    private function load(string $key): array
    {
        $raw = $this->cache->get($key);

        if (!\is_array($raw)) {
            return [];
        }

        $members = [];

        foreach ($raw as $memberKey => $row) {
            $member = PresenceMember::fromArray($row);

            if ($member !== null) {
                $members[(string) $memberKey] = $member;
            }
        }

        return $members;
    }

    /**
     * The viewed targets as a sorted list.
     *
     * Sorted as strings so the order is the same whichever side of a diff it is
     * computed on. (A `strval` used to be here, on the theory that PHP turns the
     * array key "42" into an int. The targets are the array VALUES, which stay
     * strings, so it was dead — a revert check found nothing noticed its
     * removal — and it is gone rather than kept as a comfort.)
     *
     * @param  array<array-key, string> $targets
     * @return list<string>
     */
    private static function targets(array $targets): array
    {
        $list = array_values($targets);
        sort($list, SORT_STRING);

        return $list;
    }

    /**
     * @param  array<string, PresenceMember> $members
     * @return array<string, array{u: string, e: int, t: int, v: ?string}>
     */
    private function raw(array $members): array
    {
        return array_map(static fn (PresenceMember $m): array => $m->toArray(), $members);
    }

    private function key(Channel $channel): string
    {
        return self::PREFIX . ':ch:' . $channel->name;
    }

    private function unavailable(string $operation, Channel $channel, \Throwable $e): void
    {
        // The channel NAME, never a member list or a user id.
        $this->logger?->warning('websocket.presence.unavailable', [
            'operation' => $operation,
            'channel'   => $channel->name,
            'exception' => $e::class,
            'reason'    => $e->getMessage(),
        ]);
    }
}
