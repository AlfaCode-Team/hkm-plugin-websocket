<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Domain\Channel;

/**
 * `account.<userId>` and nothing else — the shape a real authoriser has.
 *
 * Used for the cross-user test, where both connections ask for both channels
 * and each must be granted only its own. A registry keyed by channel name with
 * the decision cached passes a single-user test and fails this one.
 *
 * @internal
 */
final class OwnerOnly implements ChannelAuthorizer
{
    public function allows(Identity $identity, Channel $channel): bool
    {
        return $channel->prefix() === 'account' && $channel->identifier() === $identity->userId;
    }
}
