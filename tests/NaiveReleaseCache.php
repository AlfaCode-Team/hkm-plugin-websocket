<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\Ground\Fakes\FakeCache;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\AbstractLock;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\Lock;

/**
 * A cache whose locks release WITHOUT checking who holds them.
 *
 * The `Lock` contract is owner-checked, and the shipped fake honours that, so a
 * caller that releases a lock it never acquired is harmless against it. An
 * adapter that got this wrong would let one process free another's lock — and
 * this is the double that finds a caller relying on the adapter being right.
 *
 * @internal
 */
final class NaiveReleaseCache implements CachePort
{
    public function __construct(private readonly FakeCache $inner) {}

    public function get(string $key): mixed { return $this->inner->get($key); }

    public function set(string $key, mixed $value, ?int $ttl = null): bool { return $this->inner->set($key, $value, $ttl); }

    public function delete(string $key): bool { return $this->inner->delete($key); }

    public function has(string $key): bool { return $this->inner->has($key); }

    public function remember(string $key, int $ttl, callable $callback): mixed { return $this->inner->remember($key, $ttl, $callback); }

    public function increment(string $key, int $by = 1): int { return $this->inner->increment($key, $by); }

    public function deletePattern(string $pattern): int { return $this->inner->deletePattern($pattern); }

    public function flush(): bool { return $this->inner->flush(); }

    public function lock(string $name, int $seconds = 0, ?string $owner = null): Lock
    {
        $inner = $this->inner->lock($name, $seconds, $owner);

        return new class($name, $seconds, $inner->owner(), $inner) extends AbstractLock {
            public function __construct(string $name, int $seconds, string $owner, private readonly Lock $inner)
            {
                parent::__construct($name, $seconds, $owner);
            }

            public function acquire(): bool
            {
                return $this->inner->acquire();
            }

            public function release(): bool
            {
                $this->inner->forceRelease(); // no owner check

                return true;
            }

            public function forceRelease(): void
            {
                $this->inner->forceRelease();
            }
        };
    }

    public function restoreLock(string $name, string $owner): Lock { return $this->inner->restoreLock($name, $owner); }
}
