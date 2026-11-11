<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SystemClock;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;
use Plugins\WebSocket\Application\Services\Broadcaster;
use Plugins\WebSocket\Application\Services\ConnectionRegistry;
use Plugins\WebSocket\Application\Services\PresenceScheduler;
use Plugins\WebSocket\Application\Services\PresenceService;
use Plugins\WebSocket\Application\Services\PresenceSettings;
use Plugins\WebSocket\Application\Services\RealtimeServer;
use Plugins\WebSocket\Domain\Exceptions\ProtocolException;
use Plugins\WebSocket\Domain\Frame;
use Plugins\WebSocket\Domain\Handshake;
use Plugins\WebSocket\Domain\Message;
use Plugins\WebSocket\Domain\Opcode;
use Plugins\WebSocket\Infrastructure\Server\BusBridge;
use Plugins\WebSocket\Infrastructure\Server\DenyAllAuthorizer;
use Plugins\WebSocket\Infrastructure\Server\SwooleConnections;
use Plugins\WebSocket\Infrastructure\Server\SwooleTicker;

/**
 * `realtime:serve` — the long-running WebSocket server.
 *
 * A SERVER, NOT A REQUEST, AND THAT CHANGES THE RULES
 * --------------------------------------------------
 * Everything else in this framework runs inside one request or one job and is
 * then torn down. This process lives for weeks and holds thousands of
 * connections, which makes three ordinary habits into bugs:
 *
 *   - **per-worker state is per-worker, not per-request.** The registry below
 *     belongs to ONE worker and holds only the connections that worker
 *     accepted, which is precisely why events have to arrive over the bus
 *     rather than from a local call;
 *   - **nothing may leak.** A connection that disconnects must be removed from
 *     the registry, or the worker's memory grows for the life of the process.
 *     {@see ConnectionRegistry::forget()} is called from `close`, and also
 *     whenever a write fails, because a client can vanish without a close
 *     frame ever arriving;
 *   - **nothing may block.** One coroutine runs the bus subscription for the
 *     whole worker, so a blocking call in the message path stalls every
 *     connection that worker holds, not just the one being served.
 *
 * ONE SUBSCRIBER PER WORKER, IN ITS OWN COROUTINE
 * -----------------------------------------------
 * {@see PubSubPort::subscribe()} blocks by contract — it IS a main loop — so it
 * cannot be called on the thread that accepts connections. It runs in a
 * coroutine started at `workerStart`, which is also why OpenSwoole's
 * `enable_coroutine` is forced on here rather than left to the operator: with
 * it off, the subscription loop would block the worker and the server would
 * accept connections and never deliver anything.
 *
 * THE IDENTITY COMES FROM THE UPGRADE REQUEST, NEVER FROM A MESSAGE
 * ----------------------------------------------------------------
 * {@see self::identityFor()} resolves it once, at handshake time, from the
 * cookies and headers the browser sent. A client that could announce who it was
 * in a message could announce anybody — and the first message arrives after the
 * connection is already in the registry.
 */
final class RealtimeServeCommand extends AbstractCommand
{
    public function __construct(
        private readonly ChannelAuthorizer $authorizer = new DenyAllAuthorizer(),
        private readonly ?PubSubPort $bus = null,
        private readonly ?LoggerPort $logger = null,
        /**
         * Where presence lives. Null (no CachePort bound) disables presence
         * rather than falling back to a per-worker map, which would be wrong
         * as soon as there is a second worker.
         *
         * NOT TOUCHED before `start()`: a connection opened in this process
         * would be inherited by every forked worker and shared between them.
         * It is first used inside `workerStart`, i.e. after the fork.
         */
        private readonly ?CachePort $cache = null,
        private readonly ?ClockPort $clock = null,
        /** Resolves a socket's identity from its upgrade request. Null = everybody is a guest. */
        private readonly ?ConnectionIdentifier $identifier = null,
    ) {}

    protected function configure(): void
    {
        $this->name        = 'realtime:serve';
        $this->description = 'Run the WebSocket realtime server (long-running)';

        $this->addOption('host', '', 'Listen host; overrides WEBSOCKET_HOST', acceptsValue: true);
        $this->addOption('port', 'p', 'Listen port; overrides WEBSOCKET_PORT', acceptsValue: true);
        $this->addOption('workers', 'w', 'Worker processes; overrides WEBSOCKET_WORKERS', acceptsValue: true);
    }

    protected function handle(): int
    {
        $serverClass = match (true) {
            class_exists('OpenSwoole\\WebSocket\\Server') => 'OpenSwoole\\WebSocket\\Server',
            class_exists('Swoole\\WebSocket\\Server')     => 'Swoole\\WebSocket\\Server',
            default                                      => null,
        };

        if ($serverClass === null) {
            $this->error(
                'OpenSwoole is not loaded, so there is nothing to run the server on. '
                . 'Add `extension=openswoole` to php.ini. (The frame codec, handshake and registry '
                . 'need no extension — only the server does.)',
            );

            return self::FAILURE;
        }

        $origins = RealtimeStatusCommand::origins();

        if ($origins === []) {
            // Refused rather than started with an empty allowlist. An empty one
            // refuses every connection anyway, so starting would produce a
            // server that looks healthy and rejects every client — the failure
            // this plugin works hardest to avoid.
            $this->error(
                'WEBSOCKET_ORIGINS is empty, so every connection would be refused at the handshake. '
                . 'This is the setting that stops another site opening an authenticated socket with a '
                . 'visitor\'s cookies, so there is no permissive default. Set it and start again.',
            );

            return self::FAILURE;
        }

        if ($this->bus === null) {
            $this->error(
                'No PubSubPort is bound, so this server could hold connections open and deliver '
                . 'nothing to any of them. Bind one in withPorts() — Redis, NATS or MQTT.',
            );

            return self::FAILURE;
        }

        if ($this->authorizer instanceof DenyAllAuthorizer) {
            // A warning, not a refusal: a deployment may legitimately want the
            // server up while the authoriser is being written, and the refusals
            // are logged per attempt.
            $this->warning(
                'No ChannelAuthorizer is bound, so EVERY subscription will be refused. Bind '
                . ChannelAuthorizer::class . ' to decide who may subscribe to what.',
            );
        }

        $host    = (string) ($this->option('host') ?: RealtimeStatusCommand::host());
        $port    = (int) ($this->option('port') ?: RealtimeStatusCommand::port());
        $workers = (int) ($this->option('workers') ?: RealtimeStatusCommand::workers());
        $path    = RealtimeStatusCommand::path();

        $handshake = new Handshake(
            allowedOrigins: $origins,
            requireOrigin: RealtimeStatusCommand::flag(env('WEBSOCKET_REQUIRE_ORIGIN'), true),
            subprotocols: [RealtimeServer::PROTOCOL],
        );

        // No `@var object` annotation: PHPStan resolves $serverClass to the
        // real class and knows better than a hand-written one. The DYNAMIC
        // construction is still deliberate — naming the class in a `use`
        // statement would make this file's analysis require the extension.
        $server = new $serverClass($host, $port);

        /** @var callable $set */
        $set = [$server, 'set'];
        $set([
            'worker_num' => $workers,
            // Forced on. See the class docblock: the bus subscription is a
            // blocking loop, so without coroutines it would stall the worker
            // and the server would deliver nothing.
            'enable_coroutine'          => true,
            'open_websocket_close_frame' => true,
            'max_request'               => 0,
            // The size ceiling, applied by the EXTENSION because the extension
            // is doing the framing here. It bounds the whole reassembled
            // message, which is why there is no separate per-frame setting on
            // this transport: FrameReader's two limits are constructor
            // arguments for a transport that hands over raw bytes, and
            // declaring an env var for one that nothing on this path reads
            // would be config that does nothing — which `ground check` says so
            // about, correctly.
            'package_max_length' => max(1024, (int) (env('WEBSOCKET_MAX_MESSAGE_BYTES') ?: 8_388_608)),
            'heartbeat_check_interval'  => max(10, (int) (env('WEBSOCKET_IDLE_TIMEOUT') ?: 120)),
            'heartbeat_idle_time'       => max(20, 2 * (int) (env('WEBSOCKET_IDLE_TIMEOUT') ?: 120)),
        ]);

        $presence = PresenceSettings::fromEnv();

        if ($presence->enabled && ($this->cache === null || $this->bus === null)) {
            $this->warning(
                'Presence is DISABLED: it needs a CachePort (shared state) and a PubSubPort (announcements). '
                . 'There is deliberately no in-memory fallback — a per-worker map is wrong with more than one worker.',
            );
        }

        $this->attach($server, $handshake, $path);

        $this->success("Realtime server on ws://{$host}:{$port}{$path}");
        $this->muted('Origins : ' . implode(', ', $origins));
        $this->muted('Bus     : ' . $this->bus->describe());
        $this->muted('Workers : ' . $workers);
        $this->muted('Presence: ' . ($this->presenceService() !== null ? 'on (sweep runs in worker 0 only)' : 'off'));
        $this->newLine();

        /** @var callable $start */
        $start = [$server, 'start'];
        $start();

        return self::SUCCESS;
    }

    /**
     * Wire the four handlers. Per worker, because the state is per worker.
     *
     * @param object $server an OpenSwoole\WebSocket\Server
     */
    private function attach(object $server, Handshake $handshake, string $path): void
    {
        /** @var array<int, RealtimeServer> $realtime one per worker, set at workerStart */
        $realtime = [];
        /** @var array<int, ConnectionRegistry> $registries */
        $registries = [];

        /** @var callable $on */
        $on = [$server, 'on'];

        $on('workerStart', function (object $swoole, int $workerId) use (&$realtime, &$registries): void {
            $registry = new ConnectionRegistry(
                maxChannelsPerConnection: max(1, (int) (env('WEBSOCKET_MAX_CHANNELS') ?: 64)),
                maxConnections: max(0, (int) (env('WEBSOCKET_MAX_CONNECTIONS') ?: 10_000)),
            );

            // Built HERE, after the fork, so each worker has its own cache
            // connection — see the `$cache` constructor argument.
            $presence = $this->presenceService();

            $server = new RealtimeServer(
                $registry,
                $this->authorizer,
                new SwooleConnections($swoole),
                $this->logger,
                $presence,
            );

            $registries[$workerId] = $registry;
            $realtime[$workerId]   = $server;

            $this->subscribeToBus($server, $workerId);

            if ($presence !== null) {
                // Every worker heartbeats its own connections; PresenceScheduler
                // starts the sweep in worker 0 ONLY.
                (new PresenceScheduler(new SwooleTicker(), $presence, $server, $this->logger))->start($workerId);
            }
        });

        // Under Swoole the kernel's SIGTERM trap never fires and
        // ServerContract::stop() is never called, so this is the only place a
        // stopping worker can take its presence off the channels. Best effort:
        // a kill skips it, and the lease TTL covers that.
        $on('workerStop', function (object $swoole, int $workerId) use (&$realtime): void {
            try {
                ($realtime[$workerId] ?? null)?->presenceShutdown();
            } catch (\Throwable) {
                // Leases expire on their own.
            }
        });

        // The upgrade. Handled here rather than in the kernel's HttpPipeline
        // because a connection outlives the handler by hours, and routing it
        // through a pipeline stage would hold that stage open for its life.
        // WHY `open` IS NOT REGISTERED. Swoole documents that once an
        // `onHandshake` callback is set, `onOpen` is NEVER triggered — the
        // handshake handler owns the upgrade and is expected to do whatever
        // `open` would have. Registering `open` anyway compiles, passes every
        // unit test (they call RealtimeServer::onOpen directly) and does
        // nothing: no connection is ever registered, no `connected` frame is
        // sent, and every `subscribe` is answered "This connection is not
        // registered." It was measured that way against a real server.
        // So the registration is done at the end of the handshake, below.
        $open = function (object $swoole, object $request) use (&$realtime): void {
            $workerId = (int) self::prop($swoole, 'worker_id', 0);
            $server   = $realtime[$workerId] ?? null;

            $server?->onOpen((int) self::prop($request, 'fd', 0), $this->identityFor($request));
        };

        $on('handshake', function (object $request, object $response) use ($handshake, $path, $server, $open): bool {
            /** @var array<string, string> $headers */
            $headers = (array) self::prop($request, 'header', []);
            /** @var array<string, string> $serverVars */
            $serverVars = (array) self::prop($request, 'server', []);

            $requestPath = (string) ($serverVars['request_uri'] ?? '/');

            if ($requestPath !== $path) {
                $this->reject($response, 404, 'Not Found');

                return false;
            }

            try {
                $accepted = $handshake->accept(
                    (string) ($serverVars['request_method'] ?? 'GET'),
                    $headers,
                );
            } catch (ProtocolException $e) {
                // 403 for a policy refusal — a foreign origin — and 400 for a
                // malformed upgrade. The distinction matters to whoever is
                // reading an access log: one is an attack and the other is a
                // broken client.
                $status = $e->closeCode->value === 1008 ? 403 : 400;

                $this->logger?->warning('websocket.handshake.refused', [
                    'origin' => $headers['origin'] ?? null,
                    'reason' => $e->getMessage(),
                    'status' => $status,
                ]);

                $this->reject($response, $status, 'Upgrade refused');

                return false;
            }

            /** @var callable $header */
            $header = [$response, 'header'];

            foreach ($accepted as $name => $value) {
                $header($name, $value);
            }

            /** @var callable $status */
            $status = [$response, 'status'];
            $status(101);

            /** @var callable $end */
            $end = [$response, 'end'];
            $end();

            // Deferred, as Swoole's own documentation prescribes: the
            // connection is not established until this handler returns true,
            // so registering it (and pushing the `connected` frame) has to
            // wait for that.
            if (method_exists($server, 'defer')) {
                /** @var callable $defer */
                $defer = [$server, 'defer'];
                $defer(static function () use ($open, $server, $request): void {
                    $open($server, $request);
                });
            } else {
                $open($server, $request);
            }

            return true;
        });

        $on('message', function (object $swoole, object $frame) use (&$realtime): void {
            $workerId = (int) self::prop($swoole, 'worker_id', 0);
            $server   = $realtime[$workerId] ?? null;

            if ($server === null) {
                return;
            }

            // OpenSwoole has already done the framing, the unmasking and the
            // fragment reassembly, so what arrives is a whole message. The
            // plugin's own FrameReader is what runs under a transport that
            // hands over raw bytes; here the extension is the transport.
            $opcode = Opcode::tryFrom((int) self::prop($frame, 'opcode', 0x1)) ?? Opcode::Text;

            $data = (string) self::prop($frame, 'data', '');

            $server->onMessage(
                (int) self::prop($frame, 'fd', 0),
                $opcode->isControl()
                    ? Message::control(new Frame($opcode, $data))
                    : Message::data($opcode, $data),
            );
        });

        $on('close', function (object $swoole, int $fd) use (&$realtime): void {
            $workerId = (int) self::prop($swoole, 'worker_id', 0);

            // Always, and this is the line that stops the worker leaking: a
            // connection left in the registry is written to forever, and its
            // descriptor is eventually reused by a different client.
            ($realtime[$workerId] ?? null)?->onClose($fd);
        });
    }

    private function presenceService(): ?PresenceService
    {
        $settings = PresenceSettings::fromEnv();

        if (!$settings->enabled || $this->cache === null || $this->bus === null) {
            return null;
        }

        return new PresenceService(
            $this->cache,
            $this->clock ?? new SystemClock(),
            new Broadcaster($this->bus, trim((string) (env('WEBSOCKET_BUS_CHANNEL') ?? '')) ?: Broadcaster::DEFAULT_CHANNEL),
            $settings,
            $this->logger,
        );
    }

    /**
     * Run the bus subscription in its own coroutine.
     *
     * In a coroutine because {@see PubSubPort::subscribe()} blocks by contract.
     * On the accepting thread it would stall the whole worker, so the server
     * would hold connections open and never deliver — which is the failure
     * `realtime:status` exists to make visible.
     */
    private function subscribeToBus(RealtimeServer $server, int $workerId): void
    {
        $bus = $this->bus;

        if ($bus === null) {
            return;
        }

        $bridge  = new BusBridge($server, $this->logger);
        $channel = trim((string) (env('WEBSOCKET_BUS_CHANNEL') ?? '')) ?: 'hkm.rt.events';

        $run = function () use ($bus, $bridge, $channel, $workerId): void {
            try {
                $bus->subscribe([$channel], $bridge->handle(...));
            } catch (\Throwable $e) {
                // The subscription died. Logged rather than swallowed: a worker
                // that is accepting connections and no longer listening to the
                // bus looks completely healthy from the outside and delivers
                // nothing, which is the hardest state to diagnose.
                $this->logger?->error('websocket.bus.subscription_lost', [
                    'worker'    => $workerId,
                    'channel'   => $channel,
                    'exception' => $e::class,
                    'reason'    => $e->getMessage(),
                ]);
            }
        };

        foreach (['OpenSwoole\\Coroutine', 'Swoole\\Coroutine'] as $class) {
            if (class_exists($class) && method_exists($class, 'create')) {
                /** @var callable $create */
                $create = [$class, 'create'];
                $create($run);

                return;
            }
        }

        // No coroutine support. Running it inline would block the worker, so
        // the subscription is skipped and said so — a server that delivers
        // nothing is better understood than one that accepts nothing.
        $this->logger?->error('websocket.bus.no_coroutine', [
            'worker' => $workerId,
            'reason' => 'Coroutine::create is unavailable, so the bus subscription cannot run without '
                . 'blocking the worker. This server will accept connections and deliver no events.',
        ]);
    }

    /**
     * The connection's identity, resolved from the UPGRADE REQUEST.
     *
     * Delegated to the project's {@see ConnectionIdentifier}, because resolving
     * a session or a token means knowing which auth stack a deployment runs and
     * this plugin cannot know that. With none bound every socket is a guest —
     * public channels still work, and presence (which needs somebody to show)
     * is refused.
     *
     * What it must never do is read an identity from a MESSAGE: the first
     * message arrives after the connection is already registered, and a client
     * that could name itself could name anybody. Everything handed to the
     * identifier is untrusted request data, as its contract says; a failure of
     * the identifier is a guest, not a dropped connection.
     *
     * @param object $request an OpenSwoole\Http\Request
     */
    private function identityFor(object $request): Identity
    {
        if ($this->identifier === null) {
            return Identity::guest();
        }

        /** @var array<string, string> $headers */
        $headers = (array) self::prop($request, 'header', []);
        /** @var array<string, string> $query */
        $query = (array) self::prop($request, 'get', []);
        /** @var array<string, string> $serverVars */
        $serverVars = (array) self::prop($request, 'server', []);

        try {
            return $this->identifier->identify([
                'cookie'        => (string) ($headers['cookie'] ?? ''),
                'authorization' => (string) ($headers['authorization'] ?? ''),
                'token'         => (string) ($query['token'] ?? ''),
                'remoteIp'      => (string) ($serverVars['remote_addr'] ?? ''),
                'userAgent'     => (string) ($headers['user-agent'] ?? ''),
                'origin'        => (string) ($headers['origin'] ?? ''),
            ]);
        } catch (\Throwable $e) {
            $this->logger?->error('websocket.identifier.failed', [
                'exception' => $e::class,
                'reason'    => $e->getMessage(),
            ]);

            return Identity::guest();
        }
    }

    /**
     * Read a public property from a transport object this plugin does not type
     * against.
     *
     * `$request->fd` reads fine and does not ANALYSE fine: the parameter is
     * typed `object` on purpose — see the class docblock on why the extension
     * is not named in a `use` statement — and `object` has no properties, so
     * every such access is an unverifiable claim about a class PHPStan was
     * never shown.
     *
     * `get_object_vars()` makes the claim checkable instead of asserting it:
     * the lookup either finds the property or returns the default, which is
     * also the honest behaviour across the Swoole and OpenSwoole forks, whose
     * request objects do not expose an identical set.
     */
    private static function prop(object $source, string $name, mixed $default = null): mixed
    {
        /** @var array<string, mixed> $vars */
        $vars = get_object_vars($source);

        return $vars[$name] ?? $default;
    }

    /** @param object $response an OpenSwoole\Http\Response */
    private function reject(object $response, int $code, string $body): void
    {
        /** @var callable $status */
        $status = [$response, 'status'];
        $status($code);

        /** @var callable $end */
        $end = [$response, 'end'];
        $end($body);
    }
}
