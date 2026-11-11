<?php

declare(strict_types=1);

namespace Plugins\WebSocket\API\Contracts;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;

/**
 * Turn a connection's raw credential material into an {@see Identity}.
 *
 * WHY THE PLUGIN CANNOT DO THIS ITSELF
 * ------------------------------------
 * Resolving a session cookie or a bearer token means knowing which session
 * driver, which signing key, which token format and which user table a
 * deployment uses — all of which belong to whichever auth and session plugins
 * that project runs. A realtime plugin that implemented one of them would work
 * with exactly one stack.
 *
 * So the plugin declares the question and the project answers it, the same way
 * it answers {@see ChannelAuthorizer}.
 *
 * THE INPUT IS ATTACKER-CONTROLLED AND MUST BE VALIDATED, NOT TRUSTED
 * ------------------------------------------------------------------
 * Everything in `$credentials` arrived on a socket:
 *
 *   cookie        the raw Cookie header
 *   authorization the raw Authorization header
 *   token         a `?token=` query parameter
 *   remoteIp      best-effort, and SPOOFABLE when the edge is reachable
 *                 directly — it is a log hint, never an authorization input
 *   userAgent     a log hint
 *   origin        already checked against the allowlist before the upgrade
 *
 * An implementation must verify a signature or look a session up, exactly as it
 * would for an HTTP request. Returning a non-guest identity because a `userId`
 * appeared somewhere in the input would let anyone who can reach the realtime
 * edge — or the bus — act as any user.
 *
 * RETURN A GUEST RATHER THAN THROWING for an absent or invalid credential. An
 * anonymous connection is an ordinary state and the authorizer already knows
 * how to refuse it; an exception stops the responder's loop, which denies every
 * subscription for every client.
 */
interface ConnectionIdentifier
{
    /**
     * @param array<string, mixed> $credentials see the class docblock — every
     *                                          value is untrusted
     */
    public function identify(array $credentials): Identity;
}
