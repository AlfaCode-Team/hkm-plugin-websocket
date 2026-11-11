<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Application\Services\RealtimeServer;
use Plugins\WebSocket\Domain\Channel;
use Plugins\WebSocket\Domain\CloseCode;
use Plugins\WebSocket\Domain\Frame;
use Plugins\WebSocket\Domain\Message;
use Plugins\WebSocket\Domain\Opcode;
use Plugins\WebSocket\Infrastructure\Server\DenyAllAuthorizer;

/**
 * The server's behaviour, with the transport faked.
 *
 * THE ASSERTIONS ARE ON WHAT WAS SENT, AND TO WHICH CONNECTION
 * ------------------------------------------------------------
 * Which is the whole reason {@see RealtimeServer} takes a
 * {@see \Plugins\WebSocket\API\Contracts\Connections} rather than writing to a
 * socket. The property that matters here is not "a refusal was returned" — it
 * is that an unauthorised connection RECEIVED NOTHING, and the only way to
 * assert that is to record every write and check the recipient of each one.
 *
 * A test that asserted `subscribe` returned a denial would pass against a
 * server that denied the subscription and then delivered the events anyway.
 */
#[CoversClass(RealtimeServer::class)]
#[CoversClass(DenyAllAuthorizer::class)]
final class RealtimeServerTest extends TestCase
{
    // ── Authorisation: the tests that matter ────────────────────────────────

    /**
     * An unauthorised channel is refused AND never delivered to.
     *
     * Two assertions because they are two different failures. A server can
     * refuse the subscription correctly and still fan out to the connection —
     * if the registry was written before the authoriser was consulted, for
     * instance — and the client would receive events it was told it could not
     * have.
     */
    public function test_an_unauthorised_channel_is_refused_and_never_delivered_to(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowOnly('documents.mine'));

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribe(['documents.mine', 'documents.somebody-elses']));

        $reply = $transport->lastPayload(1);

        self::assertSame('subscribed', $reply['type']);
        self::assertSame(['documents.mine'], $reply['granted']);
        self::assertSame(['documents.somebody-elses'], $reply['denied']);

        // And now the half that a refusal alone does not prove.
        $transport->forget();

        $delivered = $server->deliver([self::channel('documents.somebody-elses')], ['id' => 7]);

        self::assertSame(0, $delivered);
        self::assertSame([], $transport->sentTo(1), 'a denied channel must never reach the connection');
    }

    /** The granted channel does arrive, so the refusal is not a blanket failure. */
    public function test_an_authorised_channel_is_delivered_to(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowOnly('documents.mine'));

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribe(['documents.mine']));
        $transport->forget();

        $delivered = $server->deliver([self::channel('documents.mine')], ['title' => 'hello']);

        self::assertSame(1, $delivered);

        $event = $transport->lastPayload(1);

        self::assertSame('event', $event['type']);
        self::assertSame(['documents.mine'], $event['channels']);
        self::assertSame(['title' => 'hello'], $event['payload']);
    }

    /**
     * Two users on the same channel name get only their own authorised one.
     *
     * The cross-tenant case, written as two connections rather than two
     * assertions on one: the bug this catches is a registry keyed by channel
     * name alone with the authorisation decision cached, which looks correct
     * for a single user.
     */
    public function test_one_users_events_do_not_reach_another(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new OwnerOnly());

        $server->onOpen(1, Identity::asUser('alice'));
        $server->onOpen(2, Identity::asUser('bob'));

        $server->onMessage(1, self::subscribe(['account.alice', 'account.bob']));
        $server->onMessage(2, self::subscribe(['account.alice', 'account.bob']));

        self::assertSame(['account.alice'], $transport->lastPayload(1)['granted']);
        self::assertSame(['account.bob'], $transport->lastPayload(2)['granted']);

        $transport->forget();

        $server->deliver([self::channel('account.alice')], ['secret' => 'alice only']);

        self::assertCount(1, $transport->sentTo(1));
        self::assertSame([], $transport->sentTo(2), "bob must not receive alice's event");
    }

    /**
     * With no authoriser bound, nothing is ever granted.
     *
     * The default. A permissive one would broadcast every event to every
     * client, with a working demo and no error anywhere.
     */
    public function test_the_default_authorizer_refuses_everything(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new DenyAllAuthorizer());

        $server->onOpen(1, Identity::asAdmin());
        $server->onMessage(1, self::subscribe(['documents.42', 'account']));

        $reply = $transport->lastPayload(1);

        self::assertSame([], $reply['granted']);
        self::assertSame(['documents.42', 'account'], $reply['denied']);
    }

    /**
     * An authoriser that throws is treated as a refusal, not as a crash.
     *
     * Its contract says it must not throw, and a project's implementation will
     * eventually do it anyway — a database outage inside a permission lookup.
     * Letting it escape would drop a connection that is behaving correctly, and
     * every other subscription on it.
     */
    public function test_an_authorizer_that_throws_denies_rather_than_dropping_the_connection(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new ThrowingAuthorizer());

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribe(['documents.42']));

        $reply = $transport->lastPayload(1);

        self::assertSame('subscribed', $reply['type']);
        self::assertSame(['documents.42'], $reply['denied']);
        self::assertSame([], $transport->closed(), 'the connection must stay open');
    }

    /**
     * A refusal does not say WHY.
     *
     * Distinguishing "no such channel" from "not yours" would make this socket
     * an existence oracle for every object in the application, probeable one
     * name at a time by anyone who can connect.
     */
    public function test_a_refusal_does_not_distinguish_missing_from_forbidden(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowOnly('documents.mine'));

        $server->onOpen(1, Identity::asUser('user-1'));

        // `documents.404` stands for a channel with no such object behind it
        // and `documents.403` for one that exists and is somebody else's. The
        // names are deliberately free of words like "exist" or "forbidden",
        // because the assertions below look for exactly those in the reply —
        // a fixture containing them would defeat its own test.
        $server->onMessage(1, self::subscribe(['documents.404', 'documents.403']));

        $reply = $transport->lastPayload(1);
        $json  = json_encode($reply) ?: '';

        // The names come back, because a client has to know which of its
        // requests failed. What must NOT come back is why.
        self::assertSame(['documents.404', 'documents.403'], $reply['denied']);
        self::assertArrayNotHasKey('reason', $reply);

        foreach (['exist', 'found', 'missing', 'unknown', 'permission', 'forbidden', 'denied_reason'] as $leak) {
            self::assertStringNotContainsStringIgnoringCase(
                $leak,
                $json,
                "the reply distinguishes why a channel was refused, which makes this socket an existence oracle",
            );
        }
    }

    // ── Revocation ──────────────────────────────────────────────────────────

    /**
     * A revoked channel stops being delivered to, without a reconnect.
     *
     * The authoriser is consulted at subscribe time only — re-checking per
     * message would put a store round trip in front of every delivery — so
     * this is the mechanism that makes a revocation take effect at once.
     */
    public function test_revoking_a_channel_stops_delivery_and_tells_the_client(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());
        $channel   = self::channel('documents.42');

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribe(['documents.42']));
        $transport->forget();

        self::assertSame(1, $server->revoke($channel));

        $notice = $transport->lastPayload(1);
        self::assertSame('unsubscribed', $notice['type']);
        self::assertSame('revoked', $notice['reason']);

        $transport->forget();

        self::assertSame(0, $server->deliver([$channel], ['after' => 'revoke']));
        self::assertSame([], $transport->sentTo(1));
    }

    // ── Connection lifecycle ────────────────────────────────────────────────

    public function test_a_new_connection_is_told_whether_it_is_authenticated(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onOpen(2, Identity::guest());

        $first = $transport->lastPayload(1);
        self::assertSame('connected', $first['type']);
        self::assertSame(RealtimeServer::PROTOCOL, $first['protocol']);
        self::assertTrue($first['identity']['authenticated']);
        self::assertSame('user-1', $first['identity']['userId']);

        $second = $transport->lastPayload(2);
        self::assertFalse($second['identity']['authenticated']);
        self::assertNull($second['identity']['userId']);
    }

    /**
     * The connect frame does not echo roles or permissions.
     *
     * They are the server's business. Echoing them hands a map of the
     * application's authorisation model to anyone who steals a session cookie.
     */
    public function test_the_connect_frame_does_not_echo_roles_or_permissions(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());

        $server->onOpen(1, new Identity(
            userId: 'user-1',
            tenantId: 'tenant-1',
            roles: ['admin', 'billing'],
            permissions: ['invoice:void'],
            tokenType: 'session',
            email: 'someone@example.com',
        ));

        $json = json_encode($transport->lastPayload(1)) ?: '';

        self::assertStringNotContainsString('admin', $json);
        self::assertStringNotContainsString('billing', $json);
        self::assertStringNotContainsString('invoice:void', $json);
        self::assertStringNotContainsString('someone@example.com', $json);
        self::assertStringNotContainsString('tenant-1', $json);
    }

    public function test_a_full_server_refuses_with_try_again_later(): void
    {
        $transport = new RecordingConnections();
        $server    = new RealtimeServer(
            new ConnectionRegistry(maxConnections: 1),
            new AllowAll(),
            $transport,
        );

        $server->onOpen(1, Identity::guest());
        $server->onOpen(2, Identity::guest());

        self::assertSame([2], $transport->closed());

        $frame = $transport->closeFrameFor(2);
        self::assertNotNull($frame);
        self::assertSame(CloseCode::TryAgainLater->value, $frame->closeCode());
    }

    /** A closed connection is forgotten, so nothing is delivered to it. */
    public function test_closing_a_connection_stops_delivery(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());
        $channel   = self::channel('documents.42');

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribe(['documents.42']));
        $server->onClose(1);
        $transport->forget();

        self::assertSame(0, $server->deliver([$channel], ['after' => 'close']));
    }

    /**
     * A write that fails forgets the connection.
     *
     * A client can vanish between the registry being read and the send being
     * attempted, which is routine on any real network. Without this the dead id
     * stays in the fan-out list and is written to on every subsequent event.
     */
    public function test_a_failed_write_forgets_the_connection(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());
        $channel   = self::channel('documents.42');

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onOpen(2, Identity::asUser('user-2'));
        $server->onMessage(1, self::subscribe(['documents.42']));
        $server->onMessage(2, self::subscribe(['documents.42']));

        $transport->breakConnection(1);

        self::assertSame(1, $server->deliver([$channel], ['first' => true]), 'only the live one counts');
        self::assertSame(1, $server->deliver([$channel], ['second' => true]), 'the dead one was dropped');
    }

    // ── Malformed and unknown messages ──────────────────────────────────────

    /** @return iterable<string, array{0: Message, 1: string}> */
    public static function badMessages(): iterable
    {
        yield 'a binary frame'        => [Message::data(Opcode::Binary, '{"type":"ping"}'), 'binary frame'];
        yield 'not json'              => [Message::data(Opcode::Text, 'subscribe please'), 'not a JSON object'];
        yield 'a json array'          => [Message::data(Opcode::Text, '["subscribe"]'), 'not a JSON object'];
        yield 'an unknown type'       => [Message::data(Opcode::Text, '{"type":"explode"}'), 'Unknown message type'];
        yield 'no type'               => [Message::data(Opcode::Text, '{"channels":["a"]}'), 'Unknown message type'];
        yield 'subscribe with no channels' => [
            Message::data(Opcode::Text, '{"type":"subscribe"}'),
            'non-empty `channels`',
        ];
        yield 'subscribe with an empty array' => [
            Message::data(Opcode::Text, '{"type":"subscribe","channels":[]}'),
            'non-empty `channels`',
        ];
    }

    /**
     * A bad message gets an error MESSAGE, not a dropped connection.
     *
     * Dropping the socket for one malformed message makes every other
     * subscription on that connection collateral damage — and the usual cause
     * is a bug in one call site of a client that is otherwise working.
     */
    #[DataProvider('badMessages')]
    public function test_a_malformed_message_is_answered_without_closing(Message $message, string $fragment): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());

        $server->onOpen(1, Identity::asUser('user-1'));
        $transport->forget();

        $server->onMessage(1, $message);

        $reply = $transport->lastPayload(1);

        self::assertSame('error', $reply['type']);
        self::assertStringContainsString($fragment, $reply['message']);
        self::assertSame([], $transport->closed(), 'the connection must stay open');
    }

    /** A single string is accepted where an array is expected. */
    public function test_channels_may_be_a_single_string(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, Message::data(Opcode::Text, '{"type":"subscribe","channels":"documents.42"}'));

        self::assertSame(['documents.42'], $transport->lastPayload(1)['granted']);
    }

    /** A JSON ping is answered with a JSON pong — the only keepalive a browser has. */
    public function test_a_json_ping_is_answered(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());

        $server->onOpen(1, Identity::guest());
        $server->onMessage(1, Message::data(Opcode::Text, '{"type":"ping"}'));

        self::assertSame('pong', $transport->lastPayload(1)['type']);
    }

    /** A protocol ping is answered with a pong carrying the same payload. */
    public function test_a_protocol_ping_is_echoed_exactly(): void
    {
        $transport = new RecordingConnections();
        $server    = $this->server($transport, new AllowAll());

        $server->onOpen(1, Identity::guest());
        $transport->forget();

        $server->onMessage(1, Message::control(Frame::ping('nonce-1234')));

        $frames = $transport->sentTo(1);

        self::assertCount(1, $frames);
        self::assertSame(Opcode::Pong, $frames[0]->opcode);
        self::assertSame('nonce-1234', $frames[0]->payload, 'a client matching payloads needs the echo exact');
    }

    /** A subscribe message naming absurdly many channels is capped. */
    public function test_the_number_of_channels_in_one_message_is_capped(): void
    {
        $transport  = new RecordingConnections();
        $authorizer = new CountingAuthorizer();
        $server     = new RealtimeServer(
            new ConnectionRegistry(maxChannelsPerConnection: 1000),
            $authorizer,
            $transport,
        );

        $names = array_map(static fn (int $i): string => "documents.{$i}", range(1, 500));

        $server->onOpen(1, Identity::asUser('user-1'));
        $server->onMessage(1, self::subscribe($names));

        self::assertLessThanOrEqual(
            64,
            $authorizer->calls,
            'one message must not be able to provoke 500 authorisation lookups',
        );
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private function server(RecordingConnections $transport, ChannelAuthorizer $authorizer): RealtimeServer
    {
        return new RealtimeServer(new ConnectionRegistry(), $authorizer, $transport);
    }

    /** @param list<string> $channels */
    private static function subscribe(array $channels): Message
    {
        return Message::data(
            Opcode::Text,
            json_encode(['type' => 'subscribe', 'channels' => $channels]) ?: '{}',
        );
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
