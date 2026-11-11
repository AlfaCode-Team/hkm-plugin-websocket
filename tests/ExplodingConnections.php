<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use Plugins\WebSocket\API\Contracts\Connections;
use Plugins\WebSocket\Domain\Frame;

/**
 * A transport whose liveness probe throws, to prove a timer callback is contained.
 *
 * @internal
 */
final class ExplodingConnections implements Connections
{
    public function send(int $connectionId, Frame $frame): bool
    {
        return true;
    }

    public function close(int $connectionId, ?Frame $frame = null): void {}

    public function isOpen(int $connectionId): bool
    {
        throw new \RuntimeException('transport exploded');
    }
}
