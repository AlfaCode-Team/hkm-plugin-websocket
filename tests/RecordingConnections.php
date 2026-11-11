<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use Plugins\WebSocket\API\Contracts\Connections;
use Plugins\WebSocket\Domain\Frame;

/**
 * A transport that records instead of writing.
 *
 * The whole reason {@see \Plugins\WebSocket\Application\Services\RealtimeServer}
 * is given a {@see Connections} rather than a socket: the property worth
 * asserting is which connection received which bytes, and the only way to check
 * that an UNAUTHORISED connection received nothing is to have a record of
 * everything that was sent.
 *
 * @internal
 */
final class RecordingConnections implements Connections
{
    /** @var array<int, list<Frame>> */
    private array $sent = [];

    /** @var list<int> */
    private array $closed = [];

    /** @var array<int, Frame> */
    private array $closeFrames = [];

    /** @var array<int, true> connections whose writes now fail */
    private array $broken = [];

    public function send(int $connectionId, Frame $frame): bool
    {
        if (isset($this->broken[$connectionId])) {
            return false;
        }

        $this->sent[$connectionId][] = $frame;

        return true;
    }

    public function close(int $connectionId, ?Frame $frame = null): void
    {
        $this->closed[] = $connectionId;

        if ($frame !== null) {
            $this->closeFrames[$connectionId] = $frame;
        }
    }

    public function isOpen(int $connectionId): bool
    {
        return !isset($this->broken[$connectionId]) && !\in_array($connectionId, $this->closed, true);
    }

    /** Make writes to $connectionId fail, as a vanished client does. */
    public function breakConnection(int $connectionId): void
    {
        $this->broken[$connectionId] = true;
    }

    /** @return list<Frame> */
    public function sentTo(int $connectionId): array
    {
        return $this->sent[$connectionId] ?? [];
    }

    /**
     * The decoded payload of the last frame sent to $connectionId.
     *
     * Fails the test rather than returning null when there is none: a test
     * asserting on a reply that was never sent should say so at the point the
     * reply is missing, not three assertions later on a null.
     *
     * @return array<string, mixed>
     */
    public function lastPayload(int $connectionId): array
    {
        $frames = $this->sentTo($connectionId);

        if ($frames === []) {
            throw new \RuntimeException("nothing was sent to connection {$connectionId}");
        }

        $decoded = json_decode($frames[\count($frames) - 1]->payload, true);

        if (!\is_array($decoded)) {
            throw new \RuntimeException("the last frame sent to {$connectionId} was not a JSON object");
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /** @return list<int> */
    public function closed(): array
    {
        return $this->closed;
    }

    public function closeFrameFor(int $connectionId): ?Frame
    {
        return $this->closeFrames[$connectionId] ?? null;
    }

    /** Clear the record, to assert on what happens NEXT. */
    public function forget(): void
    {
        $this->sent        = [];
        $this->closed      = [];
        $this->closeFrames = [];
    }
}
