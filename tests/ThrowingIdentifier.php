<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;

/**
 * Throws, to prove a broken session store becomes a GUEST rather than an error.
 *
 * The distinction is the whole point: this runs inside a responder's main loop,
 * and an exception there stops the loop — at which point the edge's requests
 * time out and every subscription on every connection is denied.
 *
 * @internal
 */
final class ThrowingIdentifier implements ConnectionIdentifier
{
    public function identify(array $credentials): Identity
    {
        throw new \RuntimeException('the session store is down');
    }
}
