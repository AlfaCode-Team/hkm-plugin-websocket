<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Server;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;

/**
 * The default: everybody is a guest.
 *
 * The same shape of default as {@see DenyAllAuthorizer}, for the same reason.
 * The alternative default — believe whatever the request says the identity is —
 * would let anything that can reach the realtime edge, or the bus behind it,
 * subscribe as any user. And it would WORK in a demo, which is what makes it
 * dangerous: the feature looks finished, and nothing is checked.
 *
 * A guest identity is not useless. Public channels still work, so a deployment
 * that only broadcasts public data needs no identifier at all. What it cannot
 * do is grant anything a real authorizer scopes to a user — and the log line
 * below is what tells an operator that is why their account channel is denied.
 */
final class GuestIdentifier implements ConnectionIdentifier
{
    public function __construct(private readonly ?LoggerPort $logger = null) {}

    public function identify(array $credentials): Identity
    {
        // Logged at NOTICE, once per connection rather than per subscribe.
        // Noisy enough to be found when somebody asks why `account.me` is
        // refused; not so noisy that a public-only deployment drowns.
        $this->logger?->notice('websocket.identifier.not_configured', [
            'effect' => 'every connection is a guest, so any channel an authorizer scopes to a user '
                . 'is denied. Public channels still work.',
            'fix' => 'bind ' . ConnectionIdentifier::class . ' to something that verifies your '
                . 'session cookie or bearer token.',
            'sawCookie' => ($credentials['cookie'] ?? '') !== '',
            'sawBearer' => ($credentials['authorization'] ?? '') !== '',
            'sawToken'  => ($credentials['token'] ?? '') !== '',
        ]);

        return Identity::guest();
    }
}
