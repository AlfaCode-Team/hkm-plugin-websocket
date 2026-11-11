<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

/**
 * The presence knobs, read once.
 *
 * Every number is clamped rather than trusted. A TTL of 0 would expire every
 * member the instant it joined; a typing TTL longer than the member TTL would
 * make a typing indicator outlive the person; a sweep interval of 0 would be a
 * timer firing in a tight loop. Each of those is a typo in a `.env`, and none of
 * them should be able to take the server down or silently make presence
 * meaningless.
 */
final readonly class PresenceSettings
{
    public int $ttl;
    public int $typingTtl;
    public int $sweepInterval;
    public int $maxMembers;

    public function __construct(
        public bool $enabled = true,
        int $ttl = 45,
        int $typingTtl = 6,
        int $sweepInterval = 10,
        int $maxMembers = 500,
    ) {
        $this->ttl           = max(9, $ttl);
        $this->typingTtl     = max(2, min($typingTtl, $this->ttl));
        $this->sweepInterval = max(2, $sweepInterval);
        $this->maxMembers    = max(1, $maxMembers);
    }

    public static function fromEnv(): self
    {
        $enabled = strtolower(trim((string) (env('WEBSOCKET_PRESENCE') ?? '')));

        return new self(
            // An unset value is ON, matching the manifest default; anything that
            // is not an affirmative is off, so a typo disables rather than
            // enables a feature that publishes who is online.
            enabled: $enabled === '' || \in_array($enabled, ['1', 'true', 'yes', 'on'], true),
            ttl: (int) (env('WEBSOCKET_PRESENCE_TTL') ?: 45),
            typingTtl: (int) (env('WEBSOCKET_PRESENCE_TYPING_TTL') ?: 6),
            sweepInterval: (int) (env('WEBSOCKET_PRESENCE_SWEEP_INTERVAL') ?: 10),
            maxMembers: (int) (env('WEBSOCKET_PRESENCE_MAX_MEMBERS') ?: 500),
        );
    }

    /**
     * How often a worker refreshes its own connections.
     *
     * A third of the TTL: two consecutive heartbeats can be missed (a slow
     * cache, a busy worker) before anyone is expired for it.
     */
    public function heartbeatInterval(): int
    {
        return max(1, intdiv($this->ttl, 3));
    }
}
