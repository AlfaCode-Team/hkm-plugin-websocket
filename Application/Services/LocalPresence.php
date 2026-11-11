<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

/**
 * Which of THIS worker's connections have joined presence, and on what.
 *
 * Per worker on purpose, and the one piece of presence state that may be. A
 * connection belongs to the process that accepted it, so "which of my sockets
 * should I keep alive" is a question only this process can answer — exactly like
 * {@see ConnectionRegistry}. The shared answer to "who is online" is in the
 * cache ({@see PresenceService}); this is only the bookkeeping that lets a
 * worker renew its own leases and remove its own members when a socket closes.
 *
 * An instance property of an object built per worker, never static: a static map
 * here would be shared by whatever else the process ran.
 */
final class LocalPresence
{
    /** @var array<int, array<string, true>> connection id → channel names joined */
    private array $joined = [];

    /** @var array<int, array<string, int>> connection id → kind → epoch second of the last accepted change */
    private array $lastAt = [];

    public function join(int $connectionId, string $channel): void
    {
        $this->joined[$connectionId][$channel] = true;
    }

    public function leave(int $connectionId, string $channel): void
    {
        unset($this->joined[$connectionId][$channel]);

        if (($this->joined[$connectionId] ?? []) === []) {
            unset($this->joined[$connectionId]);
        }
    }

    public function has(int $connectionId, string $channel): bool
    {
        return isset($this->joined[$connectionId][$channel]);
    }

    /** @return list<string> */
    public function channelsOf(int $connectionId): array
    {
        return array_keys($this->joined[$connectionId] ?? []);
    }

    /**
     * Forget a connection entirely and return what it had joined.
     *
     * @return list<string>
     */
    public function forget(int $connectionId): array
    {
        $channels = $this->channelsOf($connectionId);

        unset($this->joined[$connectionId], $this->lastAt[$connectionId]);

        return $channels;
    }

    /**
     * @return array<int, list<string>>
     */
    public function all(): array
    {
        return array_map(static fn (array $c): array => array_keys($c), $this->joined);
    }

    public function connections(): int
    {
        return \count($this->joined);
    }

    /**
     * Whether a connection is changing `$kind` more than once a second.
     *
     * Every typing or viewing change is a locked cache write that fans out to a
     * whole channel, and the cost of sending one is a few bytes — so without a
     * limit one socket can make the server do a cache round trip per message.
     * Returns true when the change is TOO SOON (and the caller drops it); records
     * the time otherwise. Whole seconds: the only clock a service may read is
     * {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort}, and one
     * change per second is the intended rate, not a precision requirement.
     */
    public function tooSoon(int $connectionId, string $kind, int $now): bool
    {
        if (($this->lastAt[$connectionId][$kind] ?? null) === $now) {
            return true;
        }

        $this->lastAt[$connectionId][$kind] = $now;

        return false;
    }
}
