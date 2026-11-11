<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Server;

use Plugins\WebSocket\API\Contracts\Ticker;

/**
 * {@see Ticker} on OpenSwoole's or Swoole's timer.
 *
 * A Swoole timer belongs to the process that created it, so it must be created
 * from `workerStart` — in the worker that should run it — and never from the
 * manager, where it would run in a process that holds no connections.
 */
final class SwooleTicker implements Ticker
{
    public function every(int $seconds, callable $tick): void
    {
        foreach (['OpenSwoole\\Timer', 'Swoole\\Timer'] as $class) {
            if (class_exists($class) && method_exists($class, 'tick')) {
                /** @var callable $schedule */
                $schedule = [$class, 'tick'];
                $schedule(max(1, $seconds) * 1000, static function () use ($tick): void {
                    try {
                        $tick();
                    } catch (\Throwable) {
                        // Reported by the caller's own guard; an exception
                        // escaping a timer callback would end the worker.
                    }
                });

                return;
            }
        }

        throw new \RuntimeException('Neither OpenSwoole\\Timer nor Swoole\\Timer is available.');
    }
}
