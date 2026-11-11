<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Application\Services\PresenceScheduler;
use Plugins\WebSocket\Application\Services\RealtimeServer;
use Plugins\WebSocket\Domain\Message;
use Plugins\WebSocket\Domain\Opcode;

/**
 * Which worker runs which timer.
 *
 * THE ASSERTIONS ARE ON BEHAVIOUR, NOT ON A COUNT ALONE
 * -----------------------------------------------------
 * "Worker 1 registered one timer" would pass against a scheduler that registered
 * a sweep wrapped in some other condition. So each test also FIRES everything
 * the worker registered against a world holding a stale member, and asserts
 * whether anybody was expired. If the `workerId === 0` guard in
 * {@see PresenceScheduler::start()} is removed, the non-zero cases fail on both.
 */
#[CoversClass(PresenceScheduler::class)]
final class PresenceSchedulerTest extends TestCase
{
    /** The test that matters most in this feature. */
    #[DataProvider('nonZeroWorkers')]
    public function test_a_non_zero_worker_does_not_run_the_sweep(int $workerId): void
    {
        [$world, $ticker, $scheduler] = $this->stage();

        $started = $scheduler->start($workerId);

        self::assertSame(['heartbeat'], $started, 'only worker 0 may sweep');
        self::assertCount(1, $ticker->registered, "worker {$workerId} registered more than its heartbeat");

        // And fire it. The member lapsed 20s ago; a sweep would announce it.
        $ticker->fireAll();
        $ticker->fireAll();

        self::assertSame([], $world->actions(), "worker {$workerId} swept and announced an expiry");
        self::assertNotNull($world->cache->peek('hkm.rt.presence:ch:documents.42'), 'the stale entry must be untouched');
        self::assertFalse(
            $world->logger->logged('warning', 'sweep'),
            'and it must not have tried',
        );
    }

    /** @return iterable<string, array{int}> */
    public static function nonZeroWorkers(): iterable
    {
        foreach ([1, 2, 3, 7, 63] as $id) {
            yield "worker {$id}" => [$id];
        }
    }

    /** The other half, so the test above is not passing because nothing ever sweeps. */
    public function test_worker_zero_runs_the_sweep_and_it_expires_the_stale_member(): void
    {
        [$world, $ticker, $scheduler] = $this->stage();

        self::assertSame(['heartbeat', 'sweep'], $scheduler->start(0));
        self::assertCount(2, $ticker->registered);

        $ticker->fireAll();

        self::assertSame(['left:ana'], $world->actions());
        self::assertNull($world->cache->peek('hkm.rt.presence:ch:documents.42'));
    }

    /** Every worker renews its own connections; that cannot be gated to one. */
    public function test_every_worker_starts_a_heartbeat(): void
    {
        foreach ([0, 1, 5] as $id) {
            [, $ticker, $scheduler] = $this->stage();

            self::assertContains('heartbeat', $scheduler->start($id), "worker {$id}");
            self::assertCount(1, array_filter(
                $ticker->intervals(),
                static fn (int $s): bool => $s === 15,
            ), "worker {$id}: a heartbeat every third of the 45s lease");
        }
    }

    public function test_the_intervals_come_from_the_settings(): void
    {
        [, $ticker, $scheduler] = $this->stage();

        $scheduler->start(0);

        self::assertSame([15, 10], $ticker->intervals(), 'heartbeat = ttl/3, sweep = sweepInterval');
    }

    /** A timer that throws must not escape into the event loop. */
    public function test_a_failing_timer_is_contained_and_logged(): void
    {
        $world   = new PresenceWorld();
        $ticker  = new RecordingTicker();
        $service = $world->worker();
        $server  = new RealtimeServer(new ConnectionRegistry(), new AllowAll(), new ExplodingConnections(), $world->logger, $service);

        $server->onOpen(1, Identity::asUser('ana'));
        $server->onMessage(1, Message::data(Opcode::Text, '{"type":"subscribe","channels":["documents.42"]}'));
        $server->onMessage(1, Message::data(Opcode::Text, '{"type":"presence.join","channel":"documents.42"}'));

        (new PresenceScheduler($ticker, $service, $server, $world->logger))->start(1);

        $ticker->fireAll(); // the heartbeat probes the transport, which throws

        $logged = $world->logger->at('error');
        self::assertCount(1, $logged);
        self::assertSame('websocket.presence.timer_failed', $logged[0]['message']);
        self::assertSame('heartbeat', $logged[0]['context']['timer']);
    }

    /**
     * @return array{PresenceWorld, RecordingTicker, PresenceScheduler}
     */
    private function stage(): array
    {
        $world   = new PresenceWorld();
        $ticker  = new RecordingTicker();
        $service = $world->worker();

        // ana joined, then went silent for 65s: past the 45s lease.
        $service->join(PresenceWorld::channel(), 'dead-worker:1', 'ana');
        $world->clock->travelSeconds(65);
        $world->forgetEvents();

        $server = new RealtimeServer(
            new ConnectionRegistry(),
            new AllowAll(),
            new RecordingConnections(),
            $world->logger,
            $service,
        );

        return [$world, $ticker, new PresenceScheduler($ticker, $service, $server, $world->logger)];
    }
}
