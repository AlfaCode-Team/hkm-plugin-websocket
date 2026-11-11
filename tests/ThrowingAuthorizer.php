<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Domain\Channel;

/**
 * Throws, despite the contract saying it must not — which a project's
 * implementation eventually will, the first time a permissions lookup meets a
 * database outage.
 *
 * @internal
 */
final class ThrowingAuthorizer implements ChannelAuthorizer
{
    public function allows(Identity $identity, Channel $channel): bool
    {
        throw new \RuntimeException('the permissions database is unreachable');
    }
}
