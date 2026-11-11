<?php

declare(strict_types=1);

namespace Plugins\WebSocket\API\Contracts;

/**
 * Serve request/reply traffic on a bus. The project supplies this.
 *
 * WHY THIS INTERFACE EXISTS AT ALL
 * --------------------------------
 * The Go edge (`edge/`) holds the sockets and asks THIS application who may
 * subscribe to what, because the authorization rule has to live next to the
 * data it queries and must have exactly one implementation. That makes a
 * request/reply channel a requirement — and `PubSubPort`, deliberately, is
 * fan-out only: it promises every subscriber every message, which is the
 * opposite of "one responder answers one asker".
 *
 * So rather than widen a kernel port whose whole value is that narrow promise,
 * this plugin declares the shape it needs and the DEPLOYMENT provides it. The
 * same inversion as {@see ChannelAuthorizer}: the plugin states what it
 * requires, the project knows which bus it runs.
 *
 * A NATS implementation is about twenty lines — subscribe, and publish the
 * answer to `$message->replyTo`. An HTTP one would work too, and a project that
 * runs only the PHP server (`realtime:serve`) needs none of this at all,
 * because there the authorizer is called in-process.
 *
 * WHY NOT COUPLE THIS PLUGIN TO THE NATS PLUGIN DIRECTLY
 * ------------------------------------------------------
 * Because a realtime plugin that imports a NATS client cannot be used with
 * Redis, or MQTT, or anything else — and because reaching into another plugin's
 * internals is the one thing the module rules forbid outright. `NatsClient` is
 * not in that plugin's `exposes`, and for a good reason: it only resolves once
 * a project has bound the port.
 */
interface RequestResponder
{
    /**
     * Subscribe to $subject and BLOCK, answering each request.
     *
     * Blocking is the contract. This is a long-running command's main loop, so
     * it returns only when {@see self::stop()} is called or the connection
     * dies.
     *
     * @param non-empty-string $subject
     * @param callable(array<string, mixed> $request): array<string, mixed> $handler
     *        receives the decoded request body and returns the reply body. It
     *        MUST NOT throw: an exception here unwinds the responder's main
     *        loop, and a realtime edge whose authorizer stopped answering
     *        denies every subscription — so one malformed request would take
     *        the whole realtime surface down.
     * @throws \RuntimeException when the subscription cannot be established or
     *         is lost. Never a silent return: a responder that quietly stopped
     *         answering is indistinguishable from an application where nobody
     *         is subscribing, and the edge reports only "denied".
     */
    public function respond(string $subject, callable $handler): void;

    /** Ask a running {@see self::respond()} to return. Signal-safe. */
    public function stop(): void;

    /** Where it is listening, for a status line. Never a credential. */
    public function describe(): string;
}
