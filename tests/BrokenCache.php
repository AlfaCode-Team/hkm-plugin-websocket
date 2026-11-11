<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\Ground\Fakes\FakeCache;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\Lock;

/**
 * A cache that is down: every call throws, as a dead Redis does.
 *
 * @internal
 */
final class BrokenCache implements CachePort
{
    public function get(string $key): mixed { throw new \RuntimeException('cache down'); }

    public function set(string $key, mixed $value, ?int $ttl = null): bool { throw new \RuntimeException('cache down'); }

    public function delete(string $key): bool { throw new \RuntimeException('cache down'); }

    public function has(string $key): bool { throw new \RuntimeException('cache down'); }

    public function remember(string $key, int $ttl, callable $callback): mixed { throw new \RuntimeException('cache down'); }

    public function increment(string $key, int $by = 1): int { throw new \RuntimeException('cache down'); }

    public function deletePattern(string $pattern): int { throw new \RuntimeException('cache down'); }

    public function flush(): bool { throw new \RuntimeException('cache down'); }

    public function lock(string $name, int $seconds = 0, ?string $owner = null): Lock
    {
        throw new \RuntimeException('cache down');
    }

    public function restoreLock(string $name, string $owner): Lock
    {
        throw new \RuntimeException('cache down');
    }
}
