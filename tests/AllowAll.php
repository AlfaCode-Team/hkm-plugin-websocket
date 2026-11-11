<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\Domain\Channel;

/**
 * Grants everything, so a test can isolate behaviour that is not about
 * authorisation.
 *
 * ONE CLASS PER FILE, and not a style preference: PSR-4 maps a class name to a
 * file name, so a second class defined inside another file is invisible to the
 * autoloader. It loads anyway if something has already required that file,
 * which makes the failure depend on test ORDER — and a data provider runs
 * before the test class is loaded, so the symptom is a missing class in one
 * run and not the next.
 *
 * @internal
 */
final class AllowAll implements ChannelAuthorizer
{
    public function allows(Identity $identity, Channel $channel): bool
    {
        return true;
    }
}
