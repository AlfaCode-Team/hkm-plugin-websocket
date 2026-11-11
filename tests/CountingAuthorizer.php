<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Domain\Channel;

/**
 * Counts calls, so a test can assert that one client message cannot provoke an
 * unbounded number of authorisation lookups.
 *
 * @internal
 */
final class CountingAuthorizer implements ChannelAuthorizer
{
    public int $calls = 0;

    /**
     * The names it was asked about, in order.
     *
     * Recorded as well as counted so a test can assert WHICH name reached the
     * authorizer — the normalised one, not the raw string — because a trimmed
     * name that is authorised while the untrimmed one is stored would let the
     * two diverge.
     *
     * @var list<string>
     */
    public array $seen = [];

    public function allows(Identity $identity, Channel $channel): bool
    {
        ++$this->calls;
        $this->seen[] = $channel->name;

        return true;
    }
}
