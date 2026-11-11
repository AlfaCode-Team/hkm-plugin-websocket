<?php

declare(strict_types=1);

namespace Plugins\WebSocket;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\NullPubSub;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort;
use Plugins\WebSocket\Application\Services\Broadcaster;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Infrastructure\Cli\RealtimeAuthorizeCommand;
use Plugins\WebSocket\Infrastructure\Cli\RealtimeServeCommand;
use Plugins\WebSocket\Infrastructure\Cli\RealtimeStatusCommand;

/**
 * WebSocket — an RFC 6455 realtime server with authorised channels.
 *
 * Solves `realtime.websocket`. No WebSocket library: the framing is a header, a
 * length in one of three forms and a four-byte XOR, and the parts that are easy
 * to get wrong are the parts a library's defaults hide — whether an unmasked
 * client frame is refused, whether a non-minimal length is refused, and whether
 * `Origin` is checked at all. The last of those is this application's only
 * defence against any page on the internet opening an authenticated socket with
 * a visitor's cookies, so it belongs in a repository that can be read next to
 * the tests that pin it.
 *
 * TWO THINGS A DEPLOYMENT MUST SUPPLY, AND NEITHER HAS A USABLE DEFAULT
 * --------------------------------------------------------------------
 * **`WEBSOCKET_ORIGINS` is required with no default**, so enabling this plugin
 * fails the boot until it is set. Deliberate: an empty allowlist refuses every
 * connection, and a permissive default would mean every deployment that did not
 * think about Cross-Site WebSocket Hijacking shipped it — invisibly, because
 * the legitimate client works either way.
 *
 * **A {@see \Plugins\WebSocket\API\Contracts\ChannelAuthorizer} must be bound,**
 * or every subscription is refused by
 * {@see \Plugins\WebSocket\Infrastructure\Server\DenyAllAuthorizer} and the
 * reason is logged on each attempt. Also deliberate, and for the stronger
 * version of the same argument: the alternative default would broadcast every
 * event to every connected client, with a demo that works perfectly and no
 * error anywhere.
 *
 * PRESENCE needs a bound CachePort (shared state) and PubSubPort (announcements)
 * and a ConnectionIdentifier (somebody to show); without a CachePort it is off.
 *
 * ENABLING THE PLUGIN DOES NOT START A SERVER. The HTTP surface is unchanged —
 * no stage, no route, no hook. `hkm cli realtime:serve` starts the long-running
 * process, and `realtime:status` reports whether the pieces it needs are
 * actually wired.
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'realtime.websocket';
    }

    /**
     * @return list<string>
     */
    public function requires(): array
    {
        return [
            // So a socket's identity can be resolved from the upgrade request
            // rather than announced by the client afterwards. A client that
            // could tell the server who it was could tell it anybody.
            'auth.identity',
        ];
    }

    /**
     * {@see \Plugins\WebSocket\API\Contracts\ChannelAuthorizer} and
     * {@see \Plugins\WebSocket\API\Contracts\Connections} are NOT listed.
     *
     * `exposes` names what this plugin binds for others to resolve, and both of
     * those run the other way: a project implements the authoriser, and the
     * transport is supplied by whichever server adapter is running. Listing
     * them would make `ground probe` right to fail, since it checks that every
     * exposed contract resolves and there is nothing to resolve in a deployment
     * that has supplied neither.
     *
     * @return list<class-string>
     */
    public function exposes(): array
    {
        return [
            Broadcaster::class,
            ConnectionRegistry::class,
        ];
    }

    public function register(ModuleContainer $container): void
    {
        // The PUBLISH side, which is what ordinary request-handling code uses.
        // Request-scoped and cheap: it holds a port and a channel name.
        $container->bind(Broadcaster::class, static fn ($c): Broadcaster => new Broadcaster(
            bus: self::bus($c),
            channel: trim((string) (env('WEBSOCKET_BUS_CHANNEL') ?? '')) ?: 'hkm.rt.events',
        ));

        // Bound so a project can read the live counts from a status endpoint.
        // NOTE: a registry resolved in an HTTP request is EMPTY — the
        // connections live in the realtime server's processes, not this one.
        // `realtime:status` reads it inside the server, where it means
        // something.
        $container->bind(ConnectionRegistry::class, static fn (): ConnectionRegistry => new ConnectionRegistry(
            maxChannelsPerConnection: max(1, (int) (env('WEBSOCKET_MAX_CHANNELS') ?: 64)),
            maxConnections: max(0, (int) (env('WEBSOCKET_MAX_CONNECTIONS') ?: 10_000)),
        ));
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        $cli->command(RealtimeServeCommand::class);
        $cli->command(RealtimeStatusCommand::class);

        // Only needed by a deployment running the Go edge (`edge/`), which
        // holds the sockets and asks THIS application every authorization
        // question over the bus — so the rule keeps exactly one
        // implementation. A deployment running `realtime:serve` calls the
        // authorizer in-process and never starts this.
        $cli->command(RealtimeAuthorizeCommand::class);

        // No HTTP stage and no route, on purpose. The upgrade is handled by the
        // realtime server's own listener rather than by the HTTP pipeline,
        // because an upgrade is not a request-response: the connection outlives
        // the handler by hours. Routing it through HttpPipeline would hold a
        // pipeline stage open for the life of the socket.
    }

    /**
     * The bus, or the null one that refuses to subscribe.
     *
     * Probed with has(), because a deployment that has not bound a PubSubPort
     * should still be able to CALL the broadcaster — an application emitting
     * events before realtime is configured is publishing into a bus nobody
     * reads, which is a no-op rather than an error. {@see NullPubSub} is the
     * asymmetric half: publishing does nothing, subscribing throws, because a
     * server started against no bus would hold connections open and deliver
     * nothing to any of them.
     */
    private static function bus(mixed $container): PubSubPort
    {
        try {
            if ($container->has(PubSubPort::class)) {
                $bound = $container->make(PubSubPort::class);

                if ($bound instanceof PubSubPort) {
                    return $bound;
                }
            }
        } catch (\Throwable) {
            // A broken adapter must not take the request down with it.
        }

        return NullPubSub::instance();
    }
}
