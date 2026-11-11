<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Domain\Channel;

/**
 * Grants exactly one channel name, so a denial can be asserted beside a grant
 * in the same reply.
 *
 * @internal
 */
final class AllowOnly implements ChannelAuthorizer
{
    public function __construct(private readonly string $allowed) {}

    public function allows(Identity $identity, Channel $channel): bool
    {
        return $channel->name === $this->allowed;
    }
}
