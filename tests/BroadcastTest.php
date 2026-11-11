<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\NullPubSub;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Application\Services\Broadcaster;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Application\Services\RealtimeServer;
use Plugins\WebSocket\Infrastructure\Server\BusBridge;

/**
 * The publish side, the bus hop, and the delivery side — joined.
 *
 * THE END-TO-END TEST IS THE POINT OF THIS FILE
 * ---------------------------------------------
 * {@see self::test_an_event_published_on_one_worker_reaches_another()} puts a
 * Broadcaster on one side of a fake bus and a RealtimeServer on the other, with
 * NO shared object between them except the bus message. That is the property
 * the whole design exists for: an event raised while handling an HTTP request
 * reaches a client held by a different process.
 *
 * A test that called `$server->deliver()` directly would prove the delivery
 * works and say nothing about the hop — and the hop is where the obvious
 * implementation fails, silently, only once more than one worker is running.
 */
#[CoversClass(Broadcaster::class)]
#[CoversClass(BusBridge::class)]
#[CoversClass(NullPubSub::class)]
final class BroadcastTest extends TestCase
{
    /**
     * Published on "worker A", delivered on "worker B".
     *
     * The two sides share nothing but the serialised bus message.
     */
    public function test_an_event_published_on_one_worker_reaches_another(): void
    {
        $bus = new RecordingBus();

        // ── worker A: handling an HTTP request, holding no connections ──
        $broadcaster = new Broadcaster($bus, 'hkm.rt.events');
        self::assertTrue($broadcaster->publish(['documents.42'], ['title' => 'renamed']));

        // ── worker B: holding the client ──
        $transport = new RecordingConnections();
        $server    = new RealtimeServer(new ConnectionRegistry(), new AllowAll(), $transport);

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribeTo('documents.42'));
        $transport->forget();

        // The bus hands the message across. Nothing else crosses.
        (new BusBridge($server))->handle('hkm.rt.events', $bus->lastPayload());

        $event = $transport->lastPayload(1);

        self::assertSame('event', $event['type']);
        self::assertSame(['documents.42'], $event['channels']);
        self::assertSame(['title' => 'renamed'], $event['payload']);
    }

    /**
     * A client on two of the published channels still receives ONE copy.
     *
     * Which is why the whole target list travels with the event rather than one
     * bus message being sent per channel: without the list the worker cannot
     * de-duplicate, and a UI that appends on receipt shows the row twice.
     */
    public function test_a_client_on_two_published_channels_receives_one_copy(): void
    {
        $bus         = new RecordingBus();
        $broadcaster = new Broadcaster($bus);

        $broadcaster->publish(['documents.42', 'collections.7.documents'], ['id' => 42]);

        $transport = new RecordingConnections();
        $server    = new RealtimeServer(new ConnectionRegistry(), new AllowAll(), $transport);

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribeTo('documents.42', 'collections.7.documents'));
        $transport->forget();

        (new BusBridge($server))->handle($broadcaster->busChannel(), $bus->lastPayload());

        self::assertCount(1, $transport->sentTo(1), 'two matching channels must not mean two deliveries');
    }

    /** One bus message carries every target, so one publish is one hop. */
    public function test_publishing_to_several_channels_is_one_bus_message(): void
    {
        $bus = new RecordingBus();

        (new Broadcaster($bus))->publish(['a.1', 'b.2', 'c.3'], ['x' => 1]);

        self::assertCount(1, $bus->published);
        self::assertSame(['a.1', 'b.2', 'c.3'], $bus->lastPayload()['channels']);
    }

    /** Naming one channel twice does not send the event to it twice. */
    public function test_a_repeated_channel_is_published_once(): void
    {
        $bus = new RecordingBus();

        (new Broadcaster($bus))->publish(['a.1', 'a.1', 'a.1'], ['x' => 1]);

        self::assertSame(['a.1'], $bus->lastPayload()['channels']);
    }

    /** An invalid name is dropped rather than failing the whole publish. */
    public function test_an_invalid_channel_name_does_not_lose_the_valid_ones(): void
    {
        $bus = new RecordingBus();

        self::assertTrue((new Broadcaster($bus))->publish(['documents.42', 'bad name', '*'], ['x' => 1]));
        self::assertSame(['documents.42'], $bus->lastPayload()['channels']);
    }

    public function test_publishing_to_no_valid_channel_does_nothing(): void
    {
        $bus = new RecordingBus();

        self::assertFalse((new Broadcaster($bus))->publish(['bad name', ''], ['x' => 1]));
        self::assertSame([], $bus->published);
    }

    /**
     * A blank configured channel falls back rather than publishing to `''`.
     *
     * Redis accepts a channel literally named nothing, so events would publish
     * successfully to a channel no worker subscribes to — a working publish
     * that delivers nothing, which is the hardest failure to see.
     */
    public function test_a_blank_bus_channel_falls_back_to_the_default(): void
    {
        $bus = new RecordingBus();

        $broadcaster = new Broadcaster($bus, '   ');

        self::assertSame(Broadcaster::DEFAULT_CHANNEL, $broadcaster->busChannel());

        $broadcaster->publish(['documents.42'], ['x' => 1]);

        self::assertSame(Broadcaster::DEFAULT_CHANNEL, $bus->published[0]['channel']);
    }

    // ── The bridge treats bus input as data ─────────────────────────────────

    /**
     * A malformed bus message is dropped, not delivered.
     *
     * The bus is a shared surface: anything that can write to the Redis or NATS
     * instance can publish on this channel — another application sharing it, a
     * staging deployment pointed at production's bus, or an attacker who
     * reached it.
     */
    public function test_a_malformed_bus_message_is_dropped(): void
    {
        $transport = new RecordingConnections();
        $server    = new RealtimeServer(new ConnectionRegistry(), new AllowAll(), $transport);
        $bridge    = new BusBridge($server);

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribeTo('documents.42'));
        $transport->forget();

        /** @var array<string, array<string, mixed>> $payloads */
        $payloads = [
            'no channels'          => ['event' => ['x' => 1]],
            'no event'             => ['channels' => ['documents.42']],
            'channels not a list'  => ['channels' => 'documents.42', 'event' => ['x' => 1]],
            'event not an object'  => ['channels' => ['documents.42'], 'event' => 'boom'],
            'empty'               => [],
            'invalid names only'  => ['channels' => ['bad name', '*'], 'event' => ['x' => 1]],
            'non-string names'    => ['channels' => [null, 42], 'event' => ['x' => 1]],
        ];

        foreach ($payloads as $label => $payload) {
            $bridge->handle('hkm.rt.events', $payload);

            self::assertSame([], $transport->sentTo(1), "[{$label}] should have been dropped");
        }
    }

    /**
     * A hostile publisher cannot reach a channel a client never subscribed to.
     *
     * The important limit on the damage. The bridge can only deliver TO
     * channels, and a connection holds only channels an authoriser granted —
     * the registry is the gate and the bridge never writes to it. So bus access
     * buys noise on an existing channel, not a new subscription.
     */
    public function test_a_bus_message_cannot_create_a_subscription(): void
    {
        $transport = new RecordingConnections();
        $server    = new RealtimeServer(new ConnectionRegistry(), new AllowOnly('documents.mine'), $transport);

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribeTo('documents.mine'));
        $transport->forget();

        // Somebody with bus access publishes to a channel this client was
        // refused, and to one it never named at all.
        (new BusBridge($server))->handle('hkm.rt.events', [
            'channels' => ['documents.somebody-elses', 'documents.never-asked-for'],
            'event'    => ['secret' => true],
        ]);

        self::assertSame([], $transport->sentTo(1));
    }

    // ── The null bus ────────────────────────────────────────────────────────

    /**
     * Publishing with no bus bound is a no-op; SUBSCRIBING throws.
     *
     * The asymmetry is the whole point of {@see NullPubSub}. An application
     * emitting events before realtime is configured is publishing into a bus
     * nobody reads, which is fine. A SERVER started against no bus would hold
     * connections open and deliver nothing to any of them, which is not.
     */
    public function test_the_null_bus_publishes_nothing_and_refuses_to_subscribe(): void
    {
        $null = NullPubSub::instance();

        self::assertSame(-1, $null->publish('hkm.rt.events', ['x' => 1]));
        self::assertStringContainsString('no PubSubPort', $null->describe());

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/cannot run without one/');

        $null->subscribe(['hkm.rt.events'], static fn (): null => null);
    }

    /** A broadcaster over the null bus still reports a failed publish honestly. */
    public function test_a_broadcaster_over_the_null_bus_reports_success_for_a_no_op(): void
    {
        // -1 means "nothing was asked", which is >= 0 false, so publish()
        // reports false. An application is entitled to know the event went
        // nowhere.
        self::assertFalse(
            (new Broadcaster(NullPubSub::instance()))->publishTo('documents.42', ['x' => 1]),
        );
    }

    private static function subscribeTo(string ...$channels): \Plugins\WebSocket\Domain\Message
    {
        return \Plugins\WebSocket\Domain\Message::data(
            \Plugins\WebSocket\Domain\Opcode::Text,
            json_encode(['type' => 'subscribe', 'channels' => array_values($channels)]) ?: '{}',
        );
    }
}
