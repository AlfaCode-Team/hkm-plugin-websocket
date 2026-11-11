<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort;

/**
 * A bus that records instead of connecting to anything.
 *
 * @internal
 */
final class RecordingBus implements PubSubPort
{
    /** @var list<array{channel: string, payload: array<string, mixed>}> */
    public array $published = [];

    public function __construct(private readonly int $subscribers = 1) {}

    public function publish(string $channel, array $payload): int
    {
        $this->published[] = ['channel' => $channel, 'payload' => $payload];

        return $this->subscribers;
    }

    public function subscribe(array $channels, callable $onMessage): void
    {
        throw new \RuntimeException('not used in these tests');
    }

    public function stop(): void {}

    public function describe(): string
    {
        return 'recording bus';
    }

    /** @return array<string, mixed> */
    public function lastPayload(): array
    {
        if ($this->published === []) {
            throw new \RuntimeException('nothing was published');
        }

        return $this->published[\count($this->published) - 1]['payload'];
    }
}
