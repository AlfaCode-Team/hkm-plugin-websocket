<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Application\Services\PresenceService;
use Plugins\WebSocket\Application\Services\PresenceSettings;
use Plugins\WebSocket\Domain\Presence\PresenceMember;

/**
 * Presence across workers, expiry, and what is announced.
 *
 * "A worker" here is a separate {@see PresenceService} over one shared cache —
 * see {@see PresenceWorld}. That is a simulation of the multi-worker case, not
 * the real thing: the real thing (forked Swoole workers, a real cache) is
 * exercised by hand and reported separately.
 */
#[CoversClass(PresenceService::class)]
#[CoversClass(PresenceMember::class)]
final class PresenceServiceTest extends TestCase
{
    private const KEY = 'hkm.rt.presence:ch:documents.42';

    // ── The reason this feature is in the cache ─────────────────────────────

    /** The test that the design exists for: a second worker sees the first's members. */
    public function test_presence_survives_a_second_worker(): void
    {
        $world   = new PresenceWorld();
        $workerA = $world->worker();
        $workerB = $world->worker();
        $channel = PresenceWorld::channel();

        self::assertTrue($workerA->join($channel, 'nodeA:1', 'ana'));
        self::assertTrue($workerB->join($channel, 'nodeB:1', 'bo'));

        $seenByA = $workerA->members($channel);
        $seenByB = $workerB->members($channel);

        self::assertSame(['ana', 'bo'], array_column($seenByA ?? [], 'userId'));
        self::assertSame($seenByA, $seenByB, 'both workers must read the same list');
    }

    /** One worker's leave is visible to the other, and announced once. */
    public function test_a_leave_on_one_worker_is_seen_by_the_other(): void
    {
        $world   = new PresenceWorld();
        $workerA = $world->worker();
        $workerB = $world->worker();
        $channel = PresenceWorld::channel();

        $workerA->join($channel, 'nodeA:1', 'ana');
        $workerB->join($channel, 'nodeB:1', 'bo');

        self::assertTrue($workerB->leave($channel, 'nodeA:1'), 'worker B removes the member worker A added');

        self::assertSame(['bo'], array_column($workerA->members($channel) ?? [], 'userId'));
        self::assertSame(['joined:ana', 'joined:bo', 'left:ana'], $world->actions());
    }

    /** Two workers writing in turn do not lose each other's updates. */
    public function test_interleaved_writes_from_two_workers_lose_nothing(): void
    {
        $world   = new PresenceWorld();
        $workers = [$world->worker(), $world->worker()];
        $channel = PresenceWorld::channel();

        foreach (range(1, 20) as $i) {
            $workers[$i % 2]->join($channel, "node{$i}:1", "user{$i}");
        }

        self::assertCount(20, $workers[0]->members($channel) ?? []);
    }

    // ── Users, not connections ──────────────────────────────────────────────

    public function test_two_tabs_are_one_user_and_closing_one_announces_nothing(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $service->join($channel, 'b:1', 'ana');

        self::assertSame(['joined:ana'], $world->actions(), 'the second tab must not announce a second join');
        self::assertCount(1, $service->members($channel) ?? []);

        $service->leave($channel, 'a:1');

        self::assertSame(['joined:ana'], $world->actions(), 'closing one of two tabs must not announce a departure');
        self::assertSame(['ana'], array_column($service->members($channel) ?? [], 'userId'));

        $service->leave($channel, 'b:1');

        self::assertSame(['joined:ana', 'left:ana'], $world->actions());
    }

    public function test_rejoining_the_same_connection_is_not_announced_again(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        $service->join(PresenceWorld::channel(), 'a:1', 'ana');
        $service->join(PresenceWorld::channel(), 'a:1', 'ana');

        self::assertSame(['joined:ana'], $world->actions());
    }

    // ── Expiry ──────────────────────────────────────────────────────────────

    /** The sweep expires a stale entry and announces it. */
    public function test_the_sweep_expires_a_stale_entry_and_announces_it(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $world->forgetEvents();

        $world->clock->travelSeconds(46); // the lease is 45s

        self::assertSame(1, $service->sweep());
        self::assertSame(['left:ana'], $world->actions());
        self::assertNull($world->cache->peek(self::KEY), 'an empty channel leaves no key behind');
        self::assertSame([], $world->cache->peek('hkm.rt.presence:index'), 'and no index entry');
    }

    /** A live entry is not touched by the sweep. */
    public function test_the_sweep_leaves_a_live_entry_alone(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        $service->join(PresenceWorld::channel(), 'a:1', 'ana');
        $world->forgetEvents();
        $world->clock->travelSeconds(44);

        self::assertSame(0, $service->sweep());
        self::assertSame([], $world->actions());
        self::assertSame(['ana'], array_column($service->members(PresenceWorld::channel()) ?? [], 'userId'));
    }

    /** Correctness does not depend on the sweeper being alive. */
    public function test_an_expired_member_is_invisible_even_if_no_sweep_ever_ran(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $world->clock->travelSeconds(46);

        self::assertSame([], $service->members($channel), 'a lapsed member must not be returned');
    }

    /** The next write drops the lapsed member and announces it — still no sweeper. */
    public function test_a_write_after_expiry_announces_the_departure(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $world->clock->travelSeconds(46);
        $service->join($channel, 'b:1', 'bo');

        self::assertSame(['joined:ana', 'joined:bo', 'left:ana'], $world->actions());
    }

    public function test_a_heartbeat_keeps_a_member_alive(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $world->clock->travelSeconds(40);
        $service->heartbeat($channel, ['a:1' => 'ana']);
        $world->clock->travelSeconds(40); // 80s in, 40s since the heartbeat

        self::assertSame(['ana'], array_column($service->members($channel) ?? [], 'userId'));
        self::assertSame(0, $service->sweep());
    }

    /** A live connection whose entry was lost is put back. */
    public function test_a_heartbeat_re_adds_a_member_that_lapsed(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $world->clock->travelSeconds(100);
        $service->heartbeat($channel, ['a:1' => 'ana']);

        self::assertSame(['ana'], array_column($service->members($channel) ?? [], 'userId'));
        // Expired and re-added in ONE write, so observers see no departure and no
        // second arrival: the user never went anywhere.
        self::assertSame(['joined:ana'], $world->actions());
    }

    public function test_the_cache_key_carries_a_ttl_so_an_abandoned_channel_does_not_live_forever(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        $service->join(PresenceWorld::channel(), 'a:1', 'ana');

        // FakeCache evaluates TTLs against the clock, so moving it past three
        // leases makes the key itself vanish — nobody swept it.
        $world->clock->travelSeconds(45 * 3 + 1);

        self::assertNull($world->cache->peek(self::KEY));
    }

    // ── Typing ──────────────────────────────────────────────────────────────

    public function test_typing_is_announced_with_an_expiry_and_only_on_change(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $world->forgetEvents();

        self::assertTrue($service->typing($channel, 'a:1', true));
        self::assertTrue($service->typing($channel, 'a:1', true), 'a refresh');
        self::assertCount(1, $world->events(), 'a refresh of an existing indicator is not another event');

        $event = $world->events()[0];
        self::assertSame('typing', $event['action']);
        self::assertTrue($event['typing']);
        self::assertSame(6, $event['expiresIn'], 'so a client can expire it without waiting for a sweep');

        self::assertTrue($service->typing($channel, 'a:1', false));
        self::assertSame(['typing:ana', 'typing:ana'], $world->actions());
        self::assertFalse($world->events()[1]['typing']);
    }

    public function test_a_non_member_cannot_set_typing(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        self::assertFalse($service->typing(PresenceWorld::channel(), 'nobody:1', true), 'typing is not a way to join');
        self::assertSame([], $world->actions());
        self::assertSame([], $service->members(PresenceWorld::channel()));
    }

    public function test_typing_lapses_on_its_own_and_the_sweep_announces_the_end(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $service->typing($channel, 'a:1', true);
        $world->forgetEvents();

        self::assertTrue($service->members($channel)[0]['typing']);

        $world->clock->travelSeconds(7); // typing ttl is 6, the lease is 45

        self::assertFalse($service->members($channel)[0]['typing'], 'a read must already say not typing');
        self::assertSame(1, $service->sweep());
        self::assertFalse($world->events()[0]['typing']);
    }

    public function test_one_tab_typing_makes_the_user_typing(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $service->join($channel, 'b:1', 'ana');
        $service->typing($channel, 'a:1', true);
        $service->typing($channel, 'b:1', true);
        $service->typing($channel, 'a:1', false);

        self::assertTrue($service->members($channel)[0]['typing'], 'still typing in the other tab');
        self::assertSame(['joined:ana', 'typing:ana'], $world->actions(), 'no false announced while a tab still types');
    }

    // ── Viewing ─────────────────────────────────────────────────────────────

    public function test_viewing_is_announced_as_the_full_set_of_targets(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $service->join($channel, 'b:1', 'ana');
        $world->forgetEvents();

        $service->viewing($channel, 'a:1', PresenceWorld::channel('invoices.7'));
        $service->viewing($channel, 'b:1', PresenceWorld::channel('invoices.9'));
        $service->viewing($channel, 'a:1', null);

        $events = $world->events();

        self::assertSame(['invoices.7'], $events[0]['targets']);
        self::assertSame(['invoices.7', 'invoices.9'], $events[1]['targets']);
        self::assertSame(['invoices.9'], $events[2]['targets']);
        self::assertSame(['invoices.9'], $service->members($channel)[0]['viewing']);
    }

    public function test_a_numeric_target_stays_a_string(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');
        $service->viewing($channel, 'a:1', PresenceWorld::channel('42'));

        // The targets are de-duplicated through array keys, and PHP turns the
        // key "42" into an int; the values stay strings, which is what is read.
        self::assertSame(['42'], $service->members($channel)[0]['viewing']);
        self::assertSame(['42'], $world->events()[1]['targets']);
    }

    public function test_a_non_member_cannot_set_viewing(): void
    {
        $world = new PresenceWorld();

        self::assertFalse($world->worker()->viewing(PresenceWorld::channel(), 'x:1', PresenceWorld::channel('a.b')));
        self::assertSame([], $world->actions());
    }

    // ── Bounds ──────────────────────────────────────────────────────────────

    public function test_a_full_channel_refuses_a_new_member_but_not_an_existing_one(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker(new PresenceSettings(maxMembers: 2));
        $channel = PresenceWorld::channel();

        self::assertTrue($service->join($channel, 'a:1', 'ana'));
        self::assertTrue($service->join($channel, 'a:2', 'bo'));
        self::assertFalse($service->join($channel, 'a:3', 'cy'), 'the third is refused, not silently dropped');
        self::assertTrue($service->join($channel, 'a:1', 'ana'), 'an existing member renewing is not a new member');

        self::assertSame(['ana', 'bo'], array_column($service->members($channel) ?? [], 'userId'));
    }

    public function test_a_corrupt_entry_is_dropped_and_the_rest_survive(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'a:1', 'ana');

        $good = $world->cache->peek(self::KEY);
        self::assertIsArray($good);
        $good['junk:1'] = 'not a member';
        $good['junk:2'] = ['u' => '', 'e' => 'soon'];
        $world->cache->set(self::KEY, $good, 100);

        self::assertSame(['ana'], array_column($service->members($channel) ?? [], 'userId'));
        self::assertTrue($service->join($channel, 'b:1', 'bo'));
        self::assertSame(['ana', 'bo'], array_column($service->members($channel) ?? [], 'userId'));
    }

    // ── Failure: presence never throws ──────────────────────────────────────

    public function test_lock_contention_reports_unavailable_and_changes_nothing(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        // Someone else holds this channel's lock; FakeCache locks never lapse,
        // so block() waits out its one second and gives up.
        self::assertTrue($world->cache->lock(self::KEY . ':lock', 5)->acquire());

        self::assertNull($service->join($channel, 'a:1', 'ana'));
        self::assertSame([], $world->actions());
        self::assertNull($world->cache->peek(self::KEY), 'an unavailable write must not half-write');
        self::assertTrue($world->logger->logged('warning', 'websocket.presence.unavailable'));
    }

    public function test_an_unavailable_log_line_carries_the_channel_and_never_a_user(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        $world->cache->lock(self::KEY . ':lock', 5)->acquire();
        $service->join(PresenceWorld::channel(), 'a:1', 'secret-user-id');

        $logged = json_encode($world->logger->records, JSON_THROW_ON_ERROR);

        self::assertStringContainsString('documents.42', $logged);
        self::assertStringNotContainsString('secret-user-id', $logged);
        self::assertStringNotContainsString('a:1', $logged);
    }

    public function test_a_failing_store_reads_as_unavailable_not_as_empty(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker(null, new BrokenCache());

        self::assertNull($service->members(PresenceWorld::channel()), 'null, so nobody mistakes an outage for an empty room');
        self::assertNull($service->join(PresenceWorld::channel(), 'a:1', 'ana'));
        self::assertNull($service->sweep(), 'a sweep over a broken store is skipped, not thrown');
    }

    public function test_the_sweep_is_skipped_while_another_sweeper_holds_the_lock(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        $service->join(PresenceWorld::channel(), 'a:1', 'ana');
        $world->clock->travelSeconds(46);
        $world->forgetEvents();

        self::assertTrue($world->cache->lock('hkm.rt.presence:sweep', 10)->acquire());

        self::assertNull($service->sweep());
        self::assertSame([], $world->actions(), 'a skipped sweep announces nothing');
    }

    /**
     * A sweep that did not get the lock must not release it.
     *
     * Against an owner-checked lock a stray release is harmless, so this uses
     * a cache whose release is not — otherwise the guard is untestable, and a
     * revert check showed nothing noticed its removal.
     */
    public function test_a_skipped_sweep_leaves_the_other_sweepers_lock_held(): void
    {
        $world = new PresenceWorld();
        $naive = new NaiveReleaseCache($world->cache);
        $other = $world->cache->lock('hkm.rt.presence:sweep', 10);

        self::assertTrue($other->acquire());
        self::assertNull($world->worker(null, $naive)->sweep());

        self::assertFalse(
            $world->cache->lock('hkm.rt.presence:sweep', 10)->acquire(),
            'the first sweeper must still hold its lock',
        );
    }

    // ── Privacy ─────────────────────────────────────────────────────────────

    public function test_an_event_carries_only_the_user_id_and_what_they_are_doing(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();
        $channel = PresenceWorld::channel();

        $service->join($channel, 'secretnode:77', 'ana');
        $service->typing($channel, 'secretnode:77', true);
        $service->viewing($channel, 'secretnode:77', PresenceWorld::channel('invoices.7'));

        $allowed = ['kind', 'action', 'channel', 'userId', 'typing', 'expiresIn', 'targets'];

        foreach ($world->events() as $event) {
            self::assertSame([], array_diff(array_keys($event), $allowed), 'an unexpected field would be a leak');
        }

        self::assertStringNotContainsString('secretnode', json_encode($world->bus->published, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('secretnode', json_encode($service->members($channel), JSON_THROW_ON_ERROR));
    }

    public function test_events_go_to_the_channel_they_describe(): void
    {
        $world   = new PresenceWorld();
        $service = $world->worker();

        $service->join(PresenceWorld::channel('documents.42'), 'a:1', 'ana');

        self::assertSame(['documents.42'], $world->bus->lastPayload()['channels']);
    }
}
