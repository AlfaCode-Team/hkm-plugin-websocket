<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;
use Plugins\WebSocket\Domain\Channel;

/**
 * Answers the Go edge's "who is this, and what may they subscribe to?".
 *
 * THIS IS THE AUTHORIZATION DECISION, IN ITS ONE AND ONLY HOME
 * -----------------------------------------------------------
 * The edge holds the sockets and knows nothing about the application. Every
 * question it has comes here, where {@see ChannelAuthorizer} can query the
 * database the answer depends on. That is the whole reason the edge is a thin
 * process rather than a realtime server in its own right: a second
 * implementation of this decision is a second place for a channel to be
 * considered readable, and the two drift.
 *
 * It is the SAME authorizer {@see RealtimeServer} calls in-process, so running
 * the PHP server and running the Go edge cannot disagree about who may see
 * what.
 *
 * IT NEVER THROWS
 * ---------------
 * Every failure becomes a denial. This runs inside a responder's main loop, and
 * an exception there stops the loop — at which point the edge's requests time
 * out, every subscription is denied, and the realtime surface is down for
 * everybody because one request was malformed.
 *
 * THE REQUEST IS UNTRUSTED INPUT, INCLUDING THE IDENTITY FIELDS
 * ------------------------------------------------------------
 * The edge is trusted to have come from the edge; it is NOT trusted to have
 * resolved an identity, because it cannot — it has no session store. So the
 * identity in the answer is resolved HERE, from the raw credential material,
 * and a `userId` sent in the request is ignored outright. Accepting one would
 * let anything that can reach the bus subscribe as anybody.
 */
final readonly class AuthorizeService
{
    public function __construct(
        private ChannelAuthorizer $authorizer,
        private ConnectionIdentifier $identifier,
        private int $maxChannels = 64,
        private ?LoggerPort $logger = null,
    ) {}

    /**
     * Handle one request from the edge.
     *
     * @param  array<string, mixed> $request `{credentials: {...}, channels: [...]}`
     * @return array<string, mixed> `{identity: {...}, granted: [...], denied: [...]}`
     */
    public function handle(array $request): array
    {
        $credentials = \is_array($request['credentials'] ?? null) ? $request['credentials'] : [];

        /** @var array<string, mixed> $credentials */
        $identity = $this->identify($credentials);

        $answer = [
            'identity' => [
                'userId'   => $identity->userId,
                'tenantId' => $identity->tenantId,
                'guest'    => $identity->isGuest(),
            ],
            // Both ALWAYS present, and always lists. The edge derives its own
            // denials from these, but a reply missing a key would still be the
            // kind of ambiguity that produces a half-made subscription.
            'granted' => [],
            'denied'  => [],
        ];

        $requested = $request['channels'] ?? [];

        if (!\is_array($requested) || $requested === []) {
            // An identify-only call. One subject and one handler for both, so
            // the identity a subscribe is checked against cannot be resolved by
            // different code from the identity the client was told about.
            return $answer;
        }

        $checked = 0;

        foreach ($requested as $raw) {
            if (!\is_string($raw)) {
                continue;
            }

            // Capped HERE as well as at the edge. The edge's cap protects the
            // edge; this one protects the DATABASE, because an authorizer is
            // usually a query per channel and the edge is not the only thing
            // that can reach this subject.
            if ($checked >= $this->maxChannels) {
                $answer['denied'][] = $raw;

                continue;
            }

            ++$checked;

            $channel = Channel::parse($raw);

            if ($channel === null) {
                $answer['denied'][] = $raw;

                continue;
            }

            if ($this->allows($identity, $channel)) {
                $answer['granted'][] = $channel->name;
            } else {
                $answer['denied'][] = $channel->name;
            }
        }

        return $answer;
    }

    /**
     * Resolve the identity, defaulting to a guest.
     *
     * A failure is a GUEST rather than an error: an unidentifiable connection
     * is anonymous, and anonymous is a state the authorizer already knows how
     * to refuse. Throwing would stop the responder.
     *
     * @param array<string, mixed> $credentials
     */
    private function identify(array $credentials): Identity
    {
        try {
            return $this->identifier->identify($credentials);
        } catch (\Throwable $e) {
            $this->logger?->error('websocket.authorize.identify_failed', [
                'error'  => $e->getMessage(),
                'effect' => 'the connection is treated as a guest, so every non-public channel is denied',
            ]);

            return Identity::guest();
        }
    }

    private function allows(Identity $identity, Channel $channel): bool
    {
        try {
            return $this->authorizer->allows($identity, $channel);
        } catch (\Throwable $e) {
            // Refusing on an outage is the safe direction, and it is the same
            // behaviour RealtimeServer has in-process — so the two paths agree
            // even when the store is down.
            $this->logger?->error('websocket.authorize.threw', [
                'channel' => $channel->name,
                'error'   => $e->getMessage(),
            ]);

            return false;
        }
    }
}
