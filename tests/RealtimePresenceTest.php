<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Application\Services\LocalPresence;
use Plugins\WebSocket\Application\Services\RealtimeServer;
use Plugins\WebSocket\Domain\Message;
use Plugins\WebSocket\Domain\Opcode;

/**
 * The `presence.*` messages, through the server, with the transport faked.
 *
 * Two {@see RealtimeServer}s over one {@see PresenceWorld} are two workers, each
 * with its own registry and its own connection ids — which collide on purpose
 * (both have a connection 1), since that is what Swoole's per-worker ids do.
 */
#[CoversClass(RealtimeServer::class)]
#[CoversClass(LocalPresence::class)]
final class RealtimePresenceTest extends TestCase
{
    // ── Who may use it ──────────────────────────────────────────────────────

    public function test_presence_needs_a_subscription_to_the_channel_first(): void
    {
        [$world, $a, $ta] = $this->worker('A');

        $a->onOpen(1, Identity::asUser('ana'));
        $a->onMessage(1, self::msg('presence.join', ['channel' => 'documents.42']));

        self::assertSame('error', $ta->lastPayload(1)['type']);
        self::assertSame([], $world->actions(), 'an unsubscribed connection must not appear in the list');
    }

    /** The authoriser's refusal also refuses presence — there is no second permission. */
    public function test_a_denied_channel_cannot_be_joined_or_read(): void
    {
        $world = new PresenceWorld();
        $ta    = new RecordingConnections();
        $a     = new RealtimeServer(new ConnectionRegistry(), new AllowOnly('documents.mine'), $ta, null, $world->worker(), 'A');

        $a->onOpen(1, Identity::asUser('ana'));
        $a->onMessage(1, self::msg('subscribe', ['channels' => ['documents.secret']]));
        $a->onMessage(1, self::msg('presence.join', ['channel' => 'documents.secret']));

        self::assertSame('error', $ta->lastPayload(1)['type']);

        $a->onMessage(1, self::msg('presence.members', ['channel' => 'documents.secret']));

        self::assertSame('error', $ta->lastPayload(1)['type'], 'the member list is not readable either');
        self::assertSame([], $world->actions());
    }

    public function test_a_guest_cannot_use_presence(): void
    {
        [$world, $a, $ta] = $this->worker('A');

        $a->onOpen(1, Identity::guest());
        $a->onMessage(1, self::msg('subscribe', ['channels' => ['documents.42']]));
        $a->onMessage(1, self::msg('presence.join', ['channel' => 'documents.42']));

        self::assertSame('error', $ta->lastPayload(1)['type']);
        self::assertSame([], $world->actions());
    }

    public function test_presence_is_refused_when_it_is_not_configured(): void
    {
        $ta = new RecordingConnections();
        $a  = new RealtimeServer(new ConnectionRegistry(), new AllowAll(), $ta);

        $a->onOpen(1, Identity::asUser('ana'));
        $a->onMessage(1, self::msg('presence.join', ['channel' => 'documents.42']));

        $reply = $ta->lastPayload(1);
        self::assertSame('error', $reply['type']);
        self::assertStringContainsString('not enabled', $reply['message']);
    }

    public function test_a_malformed_presence_message_is_answered_not_dropped(): void
    {
        [, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');

        foreach ([
            ['presence.join', []],
            ['presence.join', ['channel' => 'bad name!']],
            ['presence.join', ['channel' => ['documents.42']]],
            ['presence.nonsense', ['channel' => 'documents.42']],
            ['presence.typing', ['channel' => 'documents.42', 'typing' => 'yes']],
            ['presence.viewing', ['channel' => 'documents.42', 'target' => 'has spaces']],
            ['presence.viewing', ['channel' => 'documents.42', 'target' => 42]],
        ] as [$type, $payload]) {
            $ta->forget();
            $a->onMessage(1, self::msg($type, $payload));

            self::assertSame('error', $ta->lastPayload(1)['type'], $type . ' ' . json_encode($payload));
        }
    }

    // ── Join, and what the joiner is told ───────────────────────────────────

    public function test_join_replies_with_the_current_list_and_announces_the_arrival(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        [, $b, $tb] = $this->worker('B', $world);

        $this->join($a, $ta, 1, 'ana');
        $this->join($b, $tb, 1, 'bo'); // connection 1 on BOTH workers

        $reply = $tb->lastPayload(1);

        self::assertSame('presence.members', $reply['type']);
        self::assertSame(['ana', 'bo'], array_column($reply['members'], 'userId'));
        self::assertSame(['joined:ana', 'joined:bo'], $world->actions());
    }

    /** Both workers have a connection 1; they must be two members. */
    public function test_the_same_connection_id_on_two_workers_is_two_members(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        [, $b, $tb] = $this->worker('B', $world);

        $this->join($a, $ta, 1, 'ana');
        $this->join($b, $tb, 1, 'ana');

        $a->onClose(1);

        $b->onMessage(1, self::msg('presence.members', ['channel' => 'documents.42']));

        self::assertSame(['ana'], array_column($tb->lastPayload(1)['members'], 'userId'), 'closing A\'s socket must not remove B\'s');
        self::assertSame(['joined:ana'], $world->actions(), 'ana still has a tab open, so nothing was announced');
    }

    // ── Typing and viewing ──────────────────────────────────────────────────

    public function test_typing_and_viewing_are_announced_and_visible_to_the_other_worker(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        [, $b, $tb] = $this->worker('B', $world);

        $this->join($a, $ta, 1, 'ana');
        $this->join($b, $tb, 1, 'bo');
        $world->forgetEvents();

        $a->onMessage(1, self::msg('presence.typing', ['channel' => 'documents.42', 'typing' => true]));
        $a->onMessage(1, self::msg('presence.viewing', ['channel' => 'documents.42', 'target' => 'invoices.7']));

        self::assertSame(['typing:ana', 'viewing:ana'], $world->actions());

        $b->onMessage(1, self::msg('presence.members', ['channel' => 'documents.42']));
        $ana = $tb->lastPayload(1)['members'][0];

        self::assertSame('ana', $ana['userId']);
        self::assertTrue($ana['typing']);
        self::assertSame(['invoices.7'], $ana['viewing']);
    }

    public function test_typing_before_joining_is_refused(): void
    {
        [$world, $a, $ta] = $this->worker('A');

        $a->onOpen(1, Identity::asUser('ana'));
        $a->onMessage(1, self::msg('subscribe', ['channels' => ['documents.42']]));
        $a->onMessage(1, self::msg('presence.typing', ['channel' => 'documents.42']));

        self::assertSame('error', $ta->lastPayload(1)['type']);
        self::assertSame([], $world->actions());
    }

    /** One typing-start per second per connection; stopping is never throttled. */
    public function test_typing_start_is_throttled_but_stop_is_not(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');
        $world->forgetEvents();
        $typing = static fn (bool $on): Message => self::msg('presence.typing', ['channel' => 'documents.42', 'typing' => $on]);

        $a->onMessage(1, $typing(true));   // accepted: announces
        $a->onMessage(1, $typing(false));  // stop is never throttled
        $a->onMessage(1, $typing(true));   // same second: dropped

        self::assertSame(['typing:ana', 'typing:ana'], $world->actions(), 'start, stop; the second start was throttled');

        $world->clock->travelSeconds(1);
        $a->onMessage(1, $typing(true));

        self::assertSame(['typing:ana', 'typing:ana', 'typing:ana'], $world->actions(), 'a second later it is allowed');
    }

    public function test_viewing_changes_are_throttled(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');
        $world->forgetEvents();

        $a->onMessage(1, self::msg('presence.viewing', ['channel' => 'documents.42', 'target' => 'invoices.1']));
        $a->onMessage(1, self::msg('presence.viewing', ['channel' => 'documents.42', 'target' => 'invoices.2']));

        self::assertCount(1, $world->events(), 'a connection cannot flood the bus with viewing changes');
    }

    // ── Everything that ends a presence ─────────────────────────────────────

    public function test_closing_a_connection_removes_it_from_every_channel(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $a->onOpen(1, Identity::asUser('ana'));

        foreach (['documents.1', 'documents.2'] as $name) {
            $a->onMessage(1, self::msg('subscribe', ['channels' => [$name]]));
            $a->onMessage(1, self::msg('presence.join', ['channel' => $name]));
        }

        $a->onClose(1);

        foreach (['documents.1', 'documents.2'] as $name) {
            self::assertSame([], $world->worker()->members(PresenceWorld::channel($name)));
        }

        self::assertSame(
            ['joined:ana', 'joined:ana', 'left:ana', 'left:ana'],
            $world->actions(),
        );
    }

    public function test_unsubscribing_leaves_the_channels_presence(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');

        $a->onMessage(1, self::msg('unsubscribe', ['channels' => ['documents.42']]));

        self::assertSame([], $world->worker()->members(PresenceWorld::channel()));
        self::assertSame(['joined:ana', 'left:ana'], $world->actions());
    }

    /** A revoked permission must not leave the person listed — or typing — on the channel. */
    public function test_revoking_a_channel_removes_the_presence_of_everyone_on_it(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');
        $this->join($a, $ta, 2, 'bo');

        $a->revoke(PresenceWorld::channel());

        self::assertSame([], $world->worker()->members(PresenceWorld::channel()));
        self::assertSame(['left:ana', 'left:bo'], \array_slice($world->actions(), 2));

        // And they cannot carry on as if still joined.
        $ta->forget();
        $a->onMessage(1, self::msg('presence.typing', ['channel' => 'documents.42']));
        self::assertSame('error', $ta->lastPayload(1)['type']);
    }

    public function test_leave_is_acknowledged_and_announced(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');

        $a->onMessage(1, self::msg('presence.leave', ['channel' => 'documents.42']));

        self::assertSame('presence.left', $ta->lastPayload(1)['type']);
        self::assertSame(['joined:ana', 'left:ana'], $world->actions());
    }

    // ── Leases ──────────────────────────────────────────────────────────────

    public function test_the_heartbeat_renews_this_workers_connections(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');

        $world->clock->travelSeconds(40);
        $a->presenceHeartbeat();
        $world->clock->travelSeconds(40);

        self::assertSame(['ana'], array_column($world->worker()->members(PresenceWorld::channel()) ?? [], 'userId'));
    }

    /** Without it, the lease lapses: this is also what happens to a crashed worker. */
    public function test_without_a_heartbeat_the_lease_lapses(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');

        $world->clock->travelSeconds(46);

        self::assertSame([], $world->worker()->members(PresenceWorld::channel()));
    }

    /** A client that vanished without a close frame must not be kept online by the heartbeat. */
    public function test_the_heartbeat_closes_out_a_connection_the_transport_lost(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        $this->join($a, $ta, 1, 'ana');
        $ta->breakConnection(1);

        $world->clock->travelSeconds(10);
        $a->presenceHeartbeat();

        self::assertSame([], $world->worker()->members(PresenceWorld::channel()));
        self::assertSame(['joined:ana', 'left:ana'], $world->actions());
        self::assertSame(0, $a->presenceConnections());
    }

    // ── Shutdown ────────────────────────────────────────────────────────────

    public function test_a_stopping_worker_removes_its_own_members_and_only_its_own(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        [, $b, $tb] = $this->worker('B', $world);

        $this->join($a, $ta, 1, 'ana');
        $this->join($a, $ta, 2, 'cy');
        $this->join($b, $tb, 1, 'bo');

        $a->presenceShutdown();

        self::assertSame(['bo'], array_column($world->worker()->members(PresenceWorld::channel()) ?? [], 'userId'));
        self::assertSame(0, $a->presenceConnections());
        self::assertSame(1, $b->presenceConnections());
    }

    // ── A crashed worker: the case a process-local map cannot answer ────────

    public function test_a_crashed_workers_users_are_announced_gone_by_the_survivor_sweep(): void
    {
        [$world, $a, $ta] = $this->worker('A');
        [, $b, $tb] = $this->worker('B', $world);

        $this->join($a, $ta, 1, 'ana');
        $this->join($b, $tb, 1, 'bo');
        // Worker A is killed: no close, no shutdown, no more heartbeats. B keeps going.
        $world->clock->travelSeconds(30);
        $b->presenceHeartbeat();
        $world->clock->travelSeconds(20);
        $world->forgetEvents();

        self::assertSame(1, $world->worker()->sweep());
        self::assertSame(['left:ana'], $world->actions());
        self::assertSame(['bo'], array_column($world->worker()->members(PresenceWorld::channel()) ?? [], 'userId'));
    }

    // ── Existing behaviour is unchanged ─────────────────────────────────────

    public function test_unknown_non_presence_types_still_get_the_old_error(): void
    {
        [, $a, $ta] = $this->worker('A');
        $a->onOpen(1, Identity::asUser('ana'));
        $a->onMessage(1, self::msg('frobnicate', []));

        self::assertSame('error', $ta->lastPayload(1)['type']);
    }

    // ── Local bookkeeping ───────────────────────────────────────────────────

    public function test_local_presence_forgets_everything_about_a_connection(): void
    {
        $local = new LocalPresence();
        $local->join(1, 'documents.42');
        $local->join(1, 'documents.43');
        $local->tooSoon(1, 'typing', 100);

        self::assertSame(['documents.42', 'documents.43'], $local->forget(1));
        self::assertSame(0, $local->connections());
        self::assertFalse($local->tooSoon(1, 'typing', 100), 'the throttle record is gone with the connection');
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * One simulated worker: its own registry, its own transport, a shared world.
     *
     * @return array{PresenceWorld, RealtimeServer, RecordingConnections}
     */
    private function worker(string $nodeId, ?PresenceWorld $world = null): array
    {
        $world ??= new PresenceWorld();
        $transport = new RecordingConnections();

        return [
            $world,
            new RealtimeServer(new ConnectionRegistry(), new AllowAll(), $transport, $world->logger, $world->worker(), $nodeId),
            $transport,
        ];
    }

    /** Open, subscribe and join `documents.42` as $userId. */
    private function join(RealtimeServer $server, RecordingConnections $transport, int $connectionId, string $userId): void
    {
        $server->onOpen($connectionId, Identity::asUser($userId));
        $server->onMessage($connectionId, self::msg('subscribe', ['channels' => ['documents.42']]));
        $server->onMessage($connectionId, self::msg('presence.join', ['channel' => 'documents.42']));

        self::assertNotSame('error', $transport->lastPayload($connectionId)['type'], 'the fixture failed to join');
    }

    /** @param array<string, mixed> $payload */
    private static function msg(string $type, array $payload): Message
    {
        return Message::data(Opcode::Text, json_encode(['type' => $type] + $payload, JSON_THROW_ON_ERROR));
    }
}
