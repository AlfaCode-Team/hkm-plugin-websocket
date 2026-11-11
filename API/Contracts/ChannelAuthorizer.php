<?php

declare(strict_types=1);

namespace Plugins\WebSocket\API\Contracts;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\Domain\Channel;

/**
 * Decides whether an identity may subscribe to a channel.
 *
 * THIS CONTRACT RUNS THE OTHER WAY: A PROJECT IMPLEMENTS IT AND THIS PLUGIN
 * CALLS IT
 * -------------------------------------------------------------------------
 * The same inversion, and for the same reason, as the passkeys plugin's session
 * starter. A channel's MEANING is the deployment's, not the framework's. Only
 * the application knows that `documents.42` is readable by the members of the
 * team that owns document 42, that `account` means "this user's own events", or
 * that a tenant's channels must never cross a tenant boundary.
 *
 * A plugin that guessed would be right for one deployment and quietly wrong for
 * every other — and quietly is the problem. The failure is not an error page:
 * it is one user receiving another user's documents in real time, which looks
 * like the feature working.
 *
 * WHY THE DEFAULT REFUSES EVERYTHING
 * ----------------------------------
 * {@see \Plugins\WebSocket\Infrastructure\Server\DenyAllAuthorizer} is what runs
 * when a project has bound nothing, and it refuses every channel and logs a
 * warning naming each one.
 *
 * The alternative — a permissive default — would mean a deployment that enabled
 * this plugin and read no documentation got a server that broadcast every event
 * to every connected client, with no error anywhere and a working demo. A
 * refusing default is immediately visible in development and cannot be shipped
 * by accident: nothing arrives, the log says why, and the fix is to write the
 * class.
 *
 * CALLED ONCE PER CHANNEL PER SUBSCRIPTION, NOT PER MESSAGE
 * ---------------------------------------------------------
 * Which is a trade worth knowing about. A permission revoked after a client
 * subscribed is not noticed until it resubscribes or reconnects, because
 * re-checking on every delivery would put a database round trip in front of
 * every message to every subscriber.
 *
 * An application that needs revocation to take effect at once should publish to
 * a channel the user can be removed FROM — close the connection, or have the
 * server drop the subscription — rather than relying on this method being
 * consulted again. {@see \Plugins\WebSocket\Application\Services\ConnectionRegistry::revoke()}
 * is how that is done.
 */
interface ChannelAuthorizer
{
    /**
     * Whether $identity may receive messages published to $channel.
     *
     * MUST NOT THROW. It is called from inside the server's accept path, where
     * an exception would drop a connection that is behaving correctly. An
     * implementation that cannot reach its store should return false — refusing
     * on an outage is the safe direction, and the server logs it.
     *
     * @param Identity $identity the connection's authenticated identity;
     *                           {@see Identity::isGuest()} is true for an
     *                           anonymous socket, which an implementation must
     *                           handle rather than assume away
     */
    public function allows(Identity $identity, Channel $channel): bool;
}
