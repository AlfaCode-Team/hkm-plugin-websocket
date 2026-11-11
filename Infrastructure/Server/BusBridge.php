<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Server;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\WebSocket\Application\Services\RealtimeServer;
use Plugins\WebSocket\Domain\Channel;

/**
 * The other half of {@see \Plugins\WebSocket\Application\Services\Broadcaster}:
 * takes a message off the bus and hands it to the local connections.
 *
 * Separated from the bus subscription loop itself so it can be tested without
 * one — the loop belongs to {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort::subscribe()} and lives in the
 * server adapter, while the decision of WHAT to do with a message is here.
 *
 * EVERYTHING IT RECEIVES IS TREATED AS DATA, NOT AS INSTRUCTION
 * ------------------------------------------------------------
 * A message off the bus looks trustworthy — it was published by the
 * application's own code — and it is still parsed defensively, because the bus
 * is a shared surface. Anything that can write to the Redis or NATS instance
 * can publish on this channel: another application sharing the instance, a
 * misconfigured staging deployment pointed at production's bus, or an attacker
 * who reached the bus at all.
 *
 * So a malformed message is DROPPED AND LOGGED rather than allowed to reach the
 * server, and in particular the channel names are re-validated through
 * {@see Channel::parse()}. The important consequence is what the bridge cannot
 * do: it can only deliver to channels, and a connection only holds channels an
 * authoriser already granted it. A hostile publisher can therefore send noise
 * to a channel, which is bad, but it cannot make a connection receive a channel
 * it was never authorised for — the registry is the gate and this code never
 * writes to it.
 */
final class BusBridge
{
    public function __construct(
        private readonly RealtimeServer $server,
        private readonly ?LoggerPort $logger = null,
    ) {}

    /**
     * Handle one bus message.
     *
     * The signature matches {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort::subscribe()}'s callback, so the
     * adapter can pass `$bridge->handle(...)` straight in.
     *
     * @param array<string, mixed> $payload
     */
    public function handle(string $busChannel, array $payload): void
    {
        /** @var mixed $names */
        $names = $payload['channels'] ?? null;

        /** @var mixed $event */
        $event = $payload['event'] ?? null;

        if (!\is_array($names) || !\is_array($event)) {
            $this->logger?->warning('websocket.bus.malformed', [
                'busChannel' => $busChannel,
                'reason'     => 'expected `channels` as a list and `event` as an object',
            ]);

            return;
        }

        $channels = [];

        foreach ($names as $name) {
            if (!\is_string($name)) {
                continue;
            }

            $channel = Channel::parse($name);

            if ($channel !== null) {
                $channels[] = $channel;
            }
        }

        if ($channels === []) {
            $this->logger?->warning('websocket.bus.no_valid_channels', [
                'busChannel' => $busChannel,
            ]);

            return;
        }

        /** @var array<string, mixed> $event */
        $this->server->deliver($channels, $event);
    }
}
