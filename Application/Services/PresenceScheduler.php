<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\WebSocket\API\Contracts\Ticker;

/**
 * Decides which timers a worker starts. The worker-0 rule lives HERE.
 *
 * Two timers, and they are not alike:
 *
 *   - **heartbeat — every worker.** Each worker renews the leases of the
 *     connections IT holds; no other process can, since only this one knows they
 *     are still open. It must run everywhere. And it is what makes a crashed
 *     worker's users expire: the dead process stops renewing, and the lease
 *     lapses.
 *
 *   - **sweep — worker 0 only.** The sweep is about the whole server, not about
 *     any worker's connections. Started in every worker it is N processes
 *     expiring everybody's presence on every tick: N times the cache traffic and
 *     a race, among N sweepers, to be the one that announces each departure.
 *     Swoole forks, so "which worker am I" is the only way to pick one — the
 *     same reason `ServerContext::shouldStop()` is polled from worker 0 alone
 *     (docs/ai-context/31_SERVERS.md §6.1).
 *
 * A worker that is respawned keeps its id, so worker 0 coming back restarts the
 * sweep with no election. While it is down nothing is incorrect, only late:
 * reads and writes expire lazily, so the sweeper only controls how soon a
 * departure of an idle channel is ANNOUNCED.
 */
final class PresenceScheduler
{
    public function __construct(
        private readonly Ticker $ticker,
        private readonly PresenceService $presence,
        private readonly RealtimeServer $server,
        private readonly ?LoggerPort $logger = null,
    ) {}

    /**
     * Start this worker's timers.
     *
     * @return list<string> the timers started: `heartbeat`, plus `sweep` on worker 0
     */
    public function start(int $workerId): array
    {
        $settings = $this->presence->settings();
        $started  = [];

        $this->ticker->every($settings->heartbeatInterval(), function (): void {
            $this->guarded('heartbeat', fn () => $this->server->presenceHeartbeat());
        });
        $started[] = 'heartbeat';

        if ($workerId === 0) {
            $this->ticker->every($settings->sweepInterval, function (): void {
                $this->guarded('sweep', fn () => $this->presence->sweep());
            });
            $started[] = 'sweep';
        }

        return $started;
    }

    private function guarded(string $timer, \Closure $work): void
    {
        try {
            $work();
        } catch (\Throwable $e) {
            // A timer that throws must not take the worker down — presence is
            // not worth the connections it describes.
            $this->logger?->error('websocket.presence.timer_failed', [
                'timer'     => $timer,
                'exception' => $e::class,
                'reason'    => $e->getMessage(),
            ]);
        }
    }
}
