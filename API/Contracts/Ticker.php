<?php

declare(strict_types=1);

namespace Plugins\WebSocket\API\Contracts;

/**
 * Run something on a repeating timer, abstracted away from the event loop.
 *
 * The same reason {@see Connections} exists: the decision of WHICH worker runs a
 * timer is the part of presence that is easy to get wrong and expensive to find
 * out in production, and it cannot be tested if asking the question needs a
 * forked Swoole server. With this seam a test registers against a recording
 * ticker and asserts what a non-zero worker did and did not ask for.
 */
interface Ticker
{
    /**
     * Call $tick every $seconds, for the life of the worker that registered it.
     *
     * An exception out of $tick must not end the timer or the worker.
     */
    public function every(int $seconds, callable $tick): void;
}
