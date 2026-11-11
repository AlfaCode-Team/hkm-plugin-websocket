<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Domain\Channel;

/**
 * Channel names, and the subscription bookkeeping.
 *
 * THE CONSISTENCY ASSERTION IS THE REASON THIS FILE EXISTS
 * --------------------------------------------------------
 * {@see ConnectionRegistry} keeps the same facts in two indexes so that both
 * subscribe and publish are cheap, and the invariant — every entry in one has
 * its mirror in the other — is one a reader cannot verify by inspection.
 *
 * The consequence of breaking it is specific and nasty: a connection id left
 * behind in the fan-out index is eventually REUSED by the transport for a new
 * client, which then receives messages for channels the previous occupant of
 * that file descriptor was authorised for. So every mutating test below ends by
 * asserting {@see ConnectionRegistry::isConsistent()}, rather than trusting
 * that the removals were written symmetrically.
 */
#[CoversClass(ConnectionRegistry::class)]
#[CoversClass(Channel::class)]
final class RegistryTest extends TestCase
{
    // ── Channel names ───────────────────────────────────────────────────────

    /** @return iterable<string, array{0: string}> */
    public static function validNames(): iterable
    {
        yield 'a bare word'       => ['documents'];
        yield 'a dotted id'       => ['documents.42'];
        yield 'a uuid'            => ['documents.0191b2f7-6c1a-7b3e-9f4d-2a8c1e5d7f90'];
        yield 'nested'            => ['collections.7.documents'];
        yield 'a colon separator' => ['tenant:acme.documents.42'];
        yield 'underscores'       => ['my_channel'];
        yield 'hyphens'           => ['my-channel'];
        yield 'at the cap'        => [str_repeat('a', Channel::MAX_LENGTH)];
    }

    #[DataProvider('validNames')]
    public function test_a_valid_channel_name_parses(string $name): void
    {
        $channel = Channel::parse($name);

        self::assertNotNull($channel, "[{$name}] should be a valid channel");
        self::assertSame($name, $channel->name);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function invalidNames(): iterable
    {
        yield 'empty'            => [''];
        yield 'whitespace only'  => ['   '];
        yield 'over the cap'     => [str_repeat('a', Channel::MAX_LENGTH + 1)];
        yield 'a space inside'   => ['my channel'];
        yield 'a newline'        => ["documents\n42"];
        yield 'a null byte'      => ["documents\0"];
        yield 'a slash'          => ['documents/42'];
        yield 'a hash'           => ['documents#42'];

        // REGRESSION. PHP's `trim()` strips "\0" and "\x0B" along with real
        // whitespace, so these two were silently normalised into the valid
        // name `documents` instead of being refused. Harmless in effect — the
        // trimmed name is both what gets authorised and what gets stored, so
        // the two could not diverge — but a control byte in a channel name is a
        // broken client or a probe, and a silent repair hides both.
        yield 'a trailing null byte'   => ["documents\0"];
        yield 'a trailing vertical tab' => ["documents\x0B"];
        yield 'a leading null byte'    => ["\0documents"];

        // Not because this class would interpret them, but because it would
        // NOT: a client sending `documents.*` and being granted a channel
        // literally named `documents.*` would receive nothing and see a
        // successful subscription.
        yield 'a wildcard'       => ['documents.*'];
        yield 'a question mark'  => ['documents.?'];
        yield 'a bare wildcard'  => ['*'];

        // Almost always a client building a name from a missing variable.
        yield 'an empty segment'  => ['documents..42'];
        yield 'a leading dot'     => ['.documents'];
        yield 'a trailing dot'    => ['documents.'];
    }

    #[DataProvider('invalidNames')]
    public function test_an_invalid_channel_name_is_refused(string $name): void
    {
        self::assertNull(Channel::parse($name), "[{$name}] should be refused");
    }

    /** A name is trimmed, so a client's stray whitespace is not a new channel. */
    public function test_a_name_is_trimmed(): void
    {
        $channel = Channel::parse("  documents.42\t");

        self::assertNotNull($channel);
        self::assertSame('documents.42', $channel->name);
    }

    public function test_a_channel_splits_into_a_prefix_and_an_identifier(): void
    {
        $channel = Channel::parse('collections.7.documents');

        self::assertNotNull($channel);
        self::assertSame('collections', $channel->prefix());
        self::assertSame('7.documents', $channel->identifier());

        $bare = Channel::parse('account');

        self::assertNotNull($bare);
        self::assertSame('account', $bare->prefix());
        self::assertSame('', $bare->identifier(), 'a bare name has no identifier');
    }

    // ── Subscriptions ───────────────────────────────────────────────────────

    public function test_a_subscription_is_visible_from_both_ends(): void
    {
        $registry = new ConnectionRegistry();
        $channel  = self::channel('documents.42');

        self::assertTrue($registry->open(1, Identity::asUser('user-1')));
        self::assertTrue($registry->subscribe(1, $channel));

        self::assertSame([1], $registry->subscribersOf($channel));
        self::assertSame(['documents.42'], $registry->channelsOf(1));
        self::assertTrue($registry->isConsistent());
    }

    public function test_a_message_reaches_every_subscriber_and_nobody_else(): void
    {
        $registry = new ConnectionRegistry();
        $watched  = self::channel('documents.42');
        $other    = self::channel('documents.99');

        foreach ([1, 2, 3] as $id) {
            $registry->open($id, Identity::asUser("user-{$id}"));
        }

        $registry->subscribe(1, $watched);
        $registry->subscribe(2, $watched);
        $registry->subscribe(3, $other);

        $subscribers = $registry->subscribersOf($watched);
        sort($subscribers);

        self::assertSame([1, 2], $subscribers);
        self::assertSame([3], $registry->subscribersOf($other));
        self::assertTrue($registry->isConsistent());
    }

    /**
     * A client on two channels that both carry one event gets ONE copy.
     *
     * A UI that appends on receipt shows the row twice otherwise, which reads
     * as a duplicate record rather than as a delivery bug.
     */
    public function test_fan_out_across_channels_is_de_duplicated(): void
    {
        $registry = new ConnectionRegistry();
        $document = self::channel('documents.42');
        $parent   = self::channel('collections.7.documents');

        $registry->open(1, Identity::asUser('user-1'));
        $registry->subscribe(1, $document);
        $registry->subscribe(1, $parent);

        self::assertSame([1], $registry->subscribersOfAny([$document, $parent]));
    }

    public function test_unsubscribing_removes_it_from_both_indexes(): void
    {
        $registry = new ConnectionRegistry();
        $channel  = self::channel('documents.42');

        $registry->open(1, Identity::asUser('user-1'));
        $registry->subscribe(1, $channel);
        $registry->unsubscribe(1, $channel);

        self::assertSame([], $registry->subscribersOf($channel));
        self::assertSame([], $registry->channelsOf(1));
        self::assertSame(0, $registry->activeChannels(), 'the empty channel entry must be dropped');
        self::assertTrue($registry->isConsistent());
    }

    /**
     * Forgetting a connection clears it from the fan-out index.
     *
     * The leak with teeth. A dead id left in `$subscribers` is delivered to
     * forever — and the transport reuses connection ids, so the next client to
     * land on that descriptor inherits the subscriptions.
     */
    public function test_forgetting_a_connection_removes_every_trace_of_it(): void
    {
        $registry = new ConnectionRegistry();

        $registry->open(1, Identity::asUser('user-1'));
        $registry->open(2, Identity::asUser('user-2'));

        foreach (['documents.1', 'documents.2', 'documents.3'] as $name) {
            $registry->subscribe(1, self::channel($name));
            $registry->subscribe(2, self::channel($name));
        }

        $registry->forget(1);

        self::assertFalse($registry->has(1));
        self::assertNull($registry->identityOf(1));
        self::assertSame([], $registry->channelsOf(1));

        foreach (['documents.1', 'documents.2', 'documents.3'] as $name) {
            self::assertSame(
                [2],
                $registry->subscribersOf(self::channel($name)),
                "connection 1 is still in the fan-out list for {$name}",
            );
        }

        self::assertSame(1, $registry->connections());
        self::assertTrue($registry->isConsistent());
    }

    /** A reused connection id inherits nothing. */
    public function test_a_reused_connection_id_inherits_no_subscriptions(): void
    {
        $registry = new ConnectionRegistry();
        $channel  = self::channel('documents.42');

        $registry->open(7, Identity::asUser('first-user'));
        $registry->subscribe(7, $channel);
        $registry->forget(7);

        // The transport hands descriptor 7 to somebody else.
        $registry->open(7, Identity::asUser('second-user'));

        self::assertSame([], $registry->channelsOf(7));
        self::assertSame([], $registry->subscribersOf($channel));

        $identity = $registry->identityOf(7);
        self::assertNotNull($identity);
        self::assertSame('second-user', $identity->userId);
    }

    public function test_revoking_a_channel_drops_it_from_every_holder(): void
    {
        $registry = new ConnectionRegistry();
        $revoked  = self::channel('documents.42');
        $kept     = self::channel('documents.99');

        foreach ([1, 2, 3] as $id) {
            $registry->open($id, Identity::asUser("user-{$id}"));
            $registry->subscribe($id, $revoked);
        }

        $registry->subscribe(2, $kept);

        $affected = $registry->revoke($revoked);
        sort($affected);

        self::assertSame([1, 2, 3], $affected, 'the caller needs to know who to notify');
        self::assertSame([], $registry->subscribersOf($revoked));
        self::assertSame(['documents.99'], $registry->channelsOf(2), 'other channels survive a revoke');
        self::assertTrue($registry->isConsistent());
    }

    // ── The caps ────────────────────────────────────────────────────────────

    /**
     * A connection cannot hold more channels than its cap.
     *
     * `subscribe` is a string a client sends, and a connection is
     * unauthenticated until it subscribes — so without a cap one socket inserts
     * as many names as it can type, each costing an entry in both indexes.
     */
    public function test_a_connection_cannot_exceed_its_channel_cap(): void
    {
        $registry = new ConnectionRegistry(maxChannelsPerConnection: 3);
        $registry->open(1, Identity::asUser('user-1'));

        for ($i = 1; $i <= 3; ++$i) {
            self::assertTrue($registry->subscribe(1, self::channel("documents.{$i}")));
        }

        self::assertFalse(
            $registry->subscribe(1, self::channel('documents.4')),
            'the fourth channel must be refused',
        );

        self::assertCount(3, $registry->channelsOf(1));
        self::assertTrue($registry->isConsistent());
    }

    /**
     * Resubscribing to a channel already held succeeds and does not consume cap.
     *
     * A client reconnecting on a flaky network resubscribes to what it had;
     * counting that against the cap would make a bad connection look like an
     * abusive client and lock it out of its own channels.
     */
    public function test_resubscribing_to_a_held_channel_does_not_consume_cap(): void
    {
        $registry = new ConnectionRegistry(maxChannelsPerConnection: 2);
        $registry->open(1, Identity::asUser('user-1'));

        $channel = self::channel('documents.42');

        self::assertTrue($registry->subscribe(1, $channel));
        self::assertTrue($registry->subscribe(1, $channel));
        self::assertTrue($registry->subscribe(1, $channel));

        self::assertCount(1, $registry->channelsOf(1));
        self::assertTrue($registry->subscribe(1, self::channel('documents.99')), 'cap not consumed');
    }

    public function test_a_full_worker_refuses_a_new_connection(): void
    {
        $registry = new ConnectionRegistry(maxConnections: 2);

        self::assertTrue($registry->open(1, Identity::guest()));
        self::assertTrue($registry->open(2, Identity::guest()));
        self::assertFalse($registry->open(3, Identity::guest()), 'the worker is full');

        // …but an already-open connection is not refused by the cap.
        self::assertTrue($registry->open(1, Identity::guest()));
        self::assertSame(2, $registry->connections());
    }

    /** Subscribing an unknown connection fails rather than creating one. */
    public function test_subscribing_an_unknown_connection_is_refused(): void
    {
        $registry = new ConnectionRegistry();

        self::assertFalse($registry->subscribe(99, self::channel('documents.42')));
        self::assertSame([], $registry->subscribersOf(self::channel('documents.42')));
        self::assertTrue($registry->isConsistent());
    }

    /** Forgetting a connection that was never open is harmless. */
    public function test_forgetting_an_unknown_connection_is_harmless(): void
    {
        $registry = new ConnectionRegistry();
        $registry->open(1, Identity::asUser('user-1'));
        $registry->subscribe(1, self::channel('documents.42'));

        $registry->forget(999);

        self::assertTrue($registry->has(1));
        self::assertTrue($registry->isConsistent());
    }

    /**
     * The invariant survives a long random sequence of operations.
     *
     * The individual tests above each check one path; this one checks that no
     * ORDER of them breaks the pairing. It is the test that would catch a
     * removal written correctly in isolation and wrongly in combination.
     */
    public function test_the_indexes_stay_consistent_under_random_operations(): void
    {
        $registry = new ConnectionRegistry(maxChannelsPerConnection: 8, maxConnections: 20);
        $names    = array_map(static fn (int $i): string => "documents.{$i}", range(1, 12));

        mt_srand(20_261_108);

        for ($step = 0; $step < 4000; ++$step) {
            $id      = mt_rand(1, 25);
            $channel = self::channel($names[mt_rand(0, \count($names) - 1)]);

            match (mt_rand(0, 4)) {
                0       => (bool) $registry->open($id, Identity::asUser("user-{$id}")),
                1       => (bool) $registry->subscribe($id, $channel),
                2       => (function () use ($registry, $id, $channel): bool {
                    $registry->unsubscribe($id, $channel);

                    return true;
                })(),
                3       => (function () use ($registry, $id): bool {
                    $registry->forget($id);

                    return true;
                })(),
                default => (bool) $registry->revoke($channel),
            };

            self::assertTrue($registry->isConsistent(), "the indexes diverged at step {$step}");
        }
    }

    private static function channel(string $name): Channel
    {
        $channel = Channel::parse($name);

        if ($channel === null) {
            self::fail("the fixture [{$name}] is not a valid channel name");
        }

        return $channel;
    }
}
