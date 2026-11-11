<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use Plugins\WebSocket\API\Contracts\Ticker;

/**
 * A ticker that records what was asked of it and fires only when told to.
 *
 * @internal
 */
final class RecordingTicker implements Ticker
{
    /** @var list<array{seconds: int, tick: callable}> */
    public array $registered = [];

    public function every(int $seconds, callable $tick): void
    {
        $this->registered[] = ['seconds' => $seconds, 'tick' => $tick];
    }

    /** Run every registered callback once, in registration order. */
    public function fireAll(): void
    {
        foreach ($this->registered as $timer) {
            ($timer['tick'])();
        }
    }

    /** @return list<int> */
    public function intervals(): array
    {
        return array_column($this->registered, 'seconds');
    }
}
