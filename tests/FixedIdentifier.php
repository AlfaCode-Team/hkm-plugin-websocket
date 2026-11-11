<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;

/**
 * Identifies every connection as one fixed user.
 *
 * Its own file, not a second class inside a test file: the autoloader maps one
 * class to one path, so a second declaration in a test file is found only when
 * that file happens to have been loaded — which makes a fixture that works in
 * one test run and is "class not found" in another.
 *
 * @internal
 */
final class FixedIdentifier implements ConnectionIdentifier
{
    public function __construct(private readonly Identity $identity) {}

    public function identify(array $credentials): Identity
    {
        return $this->identity;
    }
}
