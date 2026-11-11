<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort;
use Plugins\WebSocket\Domain\Channel;

/**
 * What an application calls to send a realtime event: the PUBLISH side.
 *
 * WHY THIS DOES NOT TOUCH A CONNECTION
 * ------------------------------------
 * The obvious implementation writes straight to the subscribed sockets, and it
 * works until the server runs more than one worker — which is to say, until it
 * is deployed.
 *
 * An HTTP request is handled by one process. The realtime connections are
 * spread across all of them. So a broadcaster that wrote to a local registry
 * would reach only the clients held by the worker that served this request:
 * with four workers, a quarter of the subscribers see the update and three
 * quarters never do, at random, with no error anywhere. Under PHP-FPM it is
 * worse still — the HTTP process holds no realtime connections at all, so
 * nothing reaches anybody.
 *
 * The event therefore goes onto the bus and every realtime worker is subscribed.
 * See {@see \Plugins\WebSocket\Infrastructure\Server\BusBridge}.
 *
 * ONE BUS CHANNEL FOR EVERYTHING, WITH THE TARGETS IN THE PAYLOAD
 * --------------------------------------------------------------
 * The natural design is one bus channel per application channel —
 * `hkm.rt.documents.42` — so a worker receives only what its clients asked
 * for. It is rejected here, for two reasons.
 *
 * A worker cannot know in advance which channels its clients will subscribe to,
 * so per-channel bus topics require either a PATTERN subscription or a
 * subscribe call every time a client names a new channel. Patterns are where
 * the buses stop agreeing: Redis spells it `hkm.rt.*`, NATS `hkm.rt.>`, MQTT
 * `hkm/rt/#`, and each has its own rules about how many segments a wildcard
 * spans. Putting that into {@see PubSubPort} would push one bus's syntax into a
 * kernel contract the others have to pretend to honour. Re-subscribing per
 * channel is worse: it makes a client's `subscribe` message into a round trip
 * to the bus, so a client naming sixty channels costs sixty.
 *
 * So every event goes to ONE channel and each worker filters locally against
 * its own registry, which is a hash lookup. The cost is honest and worth
 * stating: every worker receives every event, including the ones none of its
 * clients care about. For an application publishing hundreds of events a second
 * that is nothing against the per-event delivery work; for one publishing tens
 * of thousands it becomes the bottleneck, and the answer then is to shard
 * {@see self::$channel} by event kind rather than to reach for patterns.
 *
 * IT IS FIRE AND FORGET, AND IT NEVER THROWS. {@see PubSubPort::publish()}
 * promises not to, and the reason is here: this is called after the change it
 * announces has already been committed. A bus outage must cost the
 * notification, never the request — a 500 on a successful write because the
 * realtime server was restarting is the worst trade available.
 */
final class Broadcaster
{
    public const DEFAULT_CHANNEL = 'hkm.rt.events';

    /**
     * The single bus channel realtime events travel on.
     *
     * Prefixed so realtime traffic does not collide with whatever else the
     * application publishes on the same Redis or NATS instance, and so
     * `SUBSCRIBE hkm.rt.events` is one thing an operator can watch to see every
     * event the application emits.
     *
     * NOT A PROMOTED PROPERTY, because it has to be guaranteed non-empty.
     * {@see PubSubPort::publish()} declares `non-empty-string`, and a blank
     * `WEBSOCKET_BUS_CHANNEL` would otherwise reach it as `''` — which Redis
     * accepts as a channel literally named nothing, so events would publish
     * successfully to a channel no worker is subscribed to. Falling back here
     * means the default is used rather than a channel that silently works and
     * delivers nothing.
     *
     * @var non-empty-string
     */
    private readonly string $channel;

    public function __construct(
        private readonly PubSubPort $bus,
        string $channel = self::DEFAULT_CHANNEL,
    ) {
        $trimmed = trim($channel);

        $this->channel = $trimmed !== '' ? $trimmed : self::DEFAULT_CHANNEL;
    }

    /**
     * Announce $event to every client subscribed to any of $channels.
     *
     * @param  list<string>         $channels application channel names;
     *                                        invalid ones are dropped rather
     *                                        than failing the publish, because
     *                                        losing one target is better than
     *                                        losing the notification
     * @param  array<string, mixed> $event    the payload a client receives
     * @return bool                 whether the bus accepted it
     */
    public function publish(array $channels, array $event): bool
    {
        $names = [];

        foreach ($channels as $name) {
            $channel = Channel::parse($name);

            if ($channel !== null) {
                // Keyed, so naming one channel twice does not send the event
                // to its subscribers twice.
                $names[$channel->name] = true;
            }
        }

        if ($names === []) {
            return false;
        }

        // The whole target list travels WITH the event, which is what lets a
        // worker de-duplicate: a client subscribed to both `documents.42` and
        // `collections.7.documents` must receive one copy, not two, or a UI
        // that appends on receipt shows the row twice.
        return $this->bus->publish($this->channel, [
            'channels' => array_keys($names),
            'event'    => $event,
        ]) >= 0;
    }

    /**
     * One channel, for the common case.
     *
     * @param array<string, mixed> $event
     */
    public function publishTo(string $channel, array $event): bool
    {
        return $this->publish([$channel], $event);
    }

    /**
     * The bus channel a worker must subscribe to.
     *
     * @return non-empty-string
     */
    public function busChannel(): string
    {
        return $this->channel;
    }

    /** Where events go, for a status command. Never a credential. */
    public function describe(): string
    {
        return $this->bus->describe() . " → `{$this->channel}`";
    }
}
