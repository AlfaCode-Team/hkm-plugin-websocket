<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\Ground\Fakes\FakeCache;
use AlfacodeTeam\Ground\Fakes\FakeLogger;
use AlfacodeTeam\Ground\Fakes\FrozenClock;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use Plugins\WebSocket\Application\Services\Broadcaster;
use Plugins\WebSocket\Application\Services\PresenceService;
use Plugins\WebSocket\Application\Services\PresenceSettings;
use Plugins\WebSocket\Domain\Channel;

/**
 * The state every simulated worker shares: ONE cache, ONE clock, ONE bus.
 *
 * {@see self::worker()} returns a fresh {@see PresenceService} over that shared
 * state. Two of them are two workers — the service holds no state of its own, so
 * the only thing that can make them agree is the cache, which is the property
 * under test. A fork is not needed to ask "does a second process see the
 * first's presence"; what is needed is that the two do not share an object.
 *
 * @internal
 */
final class PresenceWorld
{
    public readonly FakeCache $cache;
    public readonly FrozenClock $clock;
    public readonly RecordingBus $bus;
    public readonly FakeLogger $logger;

    public function __construct()
    {
        $this->clock  = new FrozenClock();
        $this->cache  = new FakeCache($this->clock);
        $this->bus    = new RecordingBus();
        $this->logger = new FakeLogger();
    }

    public function worker(?PresenceSettings $settings = null, ?CachePort $cache = null): PresenceService
    {
        return new PresenceService(
            $cache ?? $this->cache,
            $this->clock,
            new Broadcaster($this->bus),
            $settings ?? new PresenceSettings(ttl: 45, typingTtl: 6, sweepInterval: 10, maxMembers: 500),
            $this->logger,
        );
    }

    public static function channel(string $name = 'documents.42'): Channel
    {
        $channel = Channel::parse($name);

        if ($channel === null) {
            throw new \LogicException("{$name} is not a valid channel");
        }

        return $channel;
    }

    /**
     * The presence events published so far, as `action:userId` strings.
     *
     * @return list<string>
     */
    public function actions(): array
    {
        return array_map(
            static fn (array $e): string => $e['action'] . ':' . $e['userId'],
            $this->events(),
        );
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function events(): array
    {
        $events = [];

        foreach ($this->bus->published as $message) {
            /** @var array<string, mixed> $event */
            $event = $message['payload']['event'];

            if (($event['kind'] ?? null) === 'presence') {
                $events[] = $event;
            }
        }

        return $events;
    }

    public function forgetEvents(): void
    {
        $this->bus->published = [];
    }
}
