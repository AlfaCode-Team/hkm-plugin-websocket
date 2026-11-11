<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Server;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Domain\Channel;

/**
 * The authoriser that runs when a project has bound none: it refuses
 * everything, loudly.
 *
 * WHY THE USELESS DEFAULT IS THE RIGHT ONE
 * ----------------------------------------
 * The alternative is an authoriser that allows everything, and it would be
 * indefensible. A deployment that enabled this plugin and read nothing would
 * get a server that broadcasts every event to every connected client —
 * including events about other tenants' records — with no error anywhere and a
 * demo that works perfectly. Nobody discovers that by using the feature; they
 * discover it from a customer.
 *
 * Refusing instead is immediately visible: nothing arrives, every refusal is
 * logged by name, and the message says what to write. The feature appears
 * broken until it is configured, which for an authorisation decision is the
 * correct direction to fail.
 *
 * It logs at WARNING and on EVERY call, deliberately. A once-only notice would
 * be lost in the startup noise of a long-running server, and this is the one
 * condition where a quiet log is worse than a noisy one — the server is running
 * and doing nothing, which is otherwise indistinguishable from an application
 * that simply has no events.
 */
final class DenyAllAuthorizer implements ChannelAuthorizer
{
    public function __construct(private readonly ?LoggerPort $logger = null) {}

    public function allows(Identity $identity, Channel $channel): bool
    {
        $this->logger?->warning('websocket.authorizer.not_configured', [
            'channel' => $channel->name,
            'userId'  => $identity->isGuest() ? null : $identity->userId,
            'fix'     => 'Bind Plugins\WebSocket\API\Contracts\ChannelAuthorizer to decide which '
                . 'identities may subscribe to which channels. Until then every subscription is refused, '
                . 'because the alternative default would broadcast every event to every client.',
        ]);

        return false;
    }
}
