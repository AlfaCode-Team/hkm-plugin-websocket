<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;
use Plugins\WebSocket\Application\Services\AuthorizeService;
use Plugins\WebSocket\Domain\Channel;
use Plugins\WebSocket\Infrastructure\Server\GuestIdentifier;

/**
 * The authorization decision the Go edge asks for.
 *
 * THE TWO PROPERTIES THAT MATTER MOST
 * -----------------------------------
 * 1. {@see self::test_a_userid_in_the_request_is_ignored()} — the edge is
 *    trusted to BE the edge, never trusted to have resolved an identity,
 *    because it has no session store and cannot. A `userId` taken from the
 *    request would let anything that can reach the bus subscribe as anybody.
 *
 * 2. {@see self::test_a_throwing_authorizer_denies_and_does_not_stop_the_responder()}
 *    — this runs in a responder's main loop. An exception there stops the loop,
 *    the edge's requests time out, and every subscription on every connection
 *    is denied. One malformed request must not take the realtime surface down.
 */
#[CoversClass(AuthorizeService::class)]
#[CoversClass(GuestIdentifier::class)]
final class AuthorizeServiceTest extends TestCase
{
    private function service(
        ?ChannelAuthorizer $authorizer = null,
        ?ConnectionIdentifier $identifier = null,
        int $maxChannels = 64,
    ): AuthorizeService {
        return new AuthorizeService(
            authorizer: $authorizer ?? new AllowAll(),
            identifier: $identifier ?? new FixedIdentifier(Identity::asUser('user-1', 'tenant-1')),
            maxChannels: $maxChannels,
        );
    }

    public function test_it_answers_with_an_identity_and_two_lists(): void
    {
        $answer = $this->service(new AllowOnly('documents.42'))->handle([
            'credentials' => ['cookie' => 'session=abc'],
            'channels'    => ['documents.42', 'documents.99'],
        ]);

        self::assertSame('user-1', $answer['identity']['userId']);
        self::assertSame('tenant-1', $answer['identity']['tenantId']);
        self::assertFalse($answer['identity']['guest']);
        self::assertSame(['documents.42'], $answer['granted']);
        self::assertSame(['documents.99'], $answer['denied']);
    }

    /** Both keys are always present, even for an identify-only call. */
    public function test_granted_and_denied_are_always_present(): void
    {
        /** @var list<array<string, mixed>> $requests */
        $requests = [[], ['channels' => []], ['channels' => 'not-a-list'], ['channels' => null]];

        foreach ($requests as $request) {
            $answer = $this->service()->handle($request);

            self::assertArrayHasKey('granted', $answer);
            self::assertArrayHasKey('denied', $answer);
            self::assertSame([], $answer['granted']);
            self::assertSame([], $answer['denied']);
            self::assertArrayHasKey('identity', $answer);
        }
    }

    /**
     * A `userId` in the request is IGNORED.
     *
     * The identity comes from the identifier, which validates the credential.
     * Honouring one sent in the request would make the bus — or anything that
     * reached the edge — able to act as any user.
     */
    public function test_a_userid_in_the_request_is_ignored(): void
    {
        $answer = $this->service(new OwnerOnly())->handle([
            'credentials' => ['cookie' => '', 'userId' => 'victim'],
            'identity'    => ['userId' => 'victim'],
            'userId'      => 'victim',
            'channels'    => ['account.victim'],
        ]);

        // The identifier said user-1, so the authorizer was asked about user-1.
        self::assertSame('user-1', $answer['identity']['userId']);
        self::assertSame([], $answer['granted'], 'the claimed identity must not be honoured');
        self::assertSame(['account.victim'], $answer['denied']);
    }

    /**
     * A throwing authorizer denies, and the call returns.
     *
     * Same behaviour as RealtimeServer in-process, so the two paths agree even
     * when the store is down — and refusing on an outage is the safe direction.
     */
    public function test_a_throwing_authorizer_denies_and_does_not_stop_the_responder(): void
    {
        $answer = $this->service(new ThrowingAuthorizer())->handle([
            'credentials' => [],
            'channels'    => ['documents.42', 'documents.43'],
        ]);

        self::assertSame([], $answer['granted']);
        self::assertSame(['documents.42', 'documents.43'], $answer['denied']);
    }

    /** A throwing identifier makes the connection a guest, not an error. */
    public function test_a_throwing_identifier_becomes_a_guest(): void
    {
        $answer = $this->service(new AllowAll(), new ThrowingIdentifier())->handle([
            'credentials' => ['cookie' => 'broken'],
            'channels'    => ['public.feed'],
        ]);

        self::assertTrue($answer['identity']['guest']);
        self::assertSame('', $answer['identity']['userId']);
        // AllowAll still grants, so a public-only deployment keeps working.
        self::assertSame(['public.feed'], $answer['granted']);
    }

    public function test_a_malformed_channel_is_denied_without_reaching_the_authorizer(): void
    {
        $counting = new CountingAuthorizer();

        $answer = $this->service($counting)->handle([
            'credentials' => [],
            'channels'    => ['bad name', 'documents.*', '', 'good.1'],
        ]);

        self::assertSame(['good.1'], $answer['granted']);
        self::assertCount(3, $answer['denied']);
        self::assertSame(1, $counting->calls, 'only the valid name may cost an authorizer call');
    }

    public function test_a_non_string_channel_is_skipped(): void
    {
        $answer = $this->service()->handle([
            'credentials' => [],
            'channels'    => [null, 42, ['nested'], 'good.1'],
        ]);

        self::assertSame(['good.1'], $answer['granted']);
    }

    /**
     * The per-request cap protects the DATABASE, not the edge.
     *
     * The edge has its own cap, which protects the edge. This one matters
     * because an authorizer is usually a query per channel and the edge is not
     * the only thing that can reach this subject.
     */
    public function test_the_channel_cap_is_enforced_independently_of_the_edge(): void
    {
        $counting = new CountingAuthorizer();
        $channels = [];

        for ($i = 0; $i < 200; ++$i) {
            $channels[] = "documents.{$i}";
        }

        $answer = $this->service($counting, maxChannels: 10)->handle([
            'credentials' => [],
            'channels'    => $channels,
        ]);

        self::assertCount(10, $answer['granted']);
        self::assertCount(190, $answer['denied']);
        self::assertSame(10, $counting->calls, 'the cap must bound the authorizer calls, not just the answer');
    }

    public function test_channel_names_are_normalised_before_being_authorised(): void
    {
        $counting = new CountingAuthorizer();

        $answer = $this->service($counting)->handle([
            'credentials' => [],
            'channels'    => ['  documents.42  '],
        ]);

        // The TRIMMED name is what is authorised and what is returned, so the
        // two cannot diverge.
        self::assertSame(['documents.42'], $answer['granted']);
        self::assertSame(['documents.42'], $counting->seen);
    }

    public function test_the_guest_identifier_is_the_default_and_identifies_nobody(): void
    {
        $identity = (new GuestIdentifier())->identify([
            'cookie'        => 'session=looks-real',
            'authorization' => 'Bearer looks-real',
            'token'         => 'looks-real',
        ]);

        // Credentials that LOOK valid must still produce a guest: believing
        // them is the default that would make a demo work and check nothing.
        self::assertTrue($identity->isGuest());
        self::assertSame('', $identity->userId);
    }
}

