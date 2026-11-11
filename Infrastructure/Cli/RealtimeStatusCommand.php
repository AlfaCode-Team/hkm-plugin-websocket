<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\NullPubSub;
use Plugins\WebSocket\Application\Services\PresenceSettings;
use Plugins\WebSocket\Domain\Handshake;

/**
 * `realtime:status` — whether this deployment's realtime server would work.
 *
 * WHY A STATUS COMMAND IS NOT A LUXURY HERE
 * -----------------------------------------
 * Every way this plugin can be misconfigured produces the SAME symptom:
 * nothing arrives. A client connects, the handshake succeeds, subscriptions are
 * acknowledged, and no events ever come — and that looks identical to an
 * application where nothing is happening.
 *
 * There are five distinct causes and the server cannot tell them apart from the
 * inside, so this command names each one:
 *
 *   1. no `PubSubPort` bound, so nothing crosses between workers;
 *   2. no `ChannelAuthorizer` bound, so every subscription is refused;
 *   3. `WEBSOCKET_ORIGINS` wrong, so the browser is refused at the handshake —
 *      which the server DOES see, unlike the client-side SecurityError that a
 *      wrong relying-party id produces for passkeys;
 *   4. the application never calls the broadcaster, so nothing is published;
 *   5. OpenSwoole absent, so the server cannot start at all.
 *
 * It checks what it can and NAMES what it cannot, rather than reporting a
 * green tick for the parts it never looked at.
 */
final class RealtimeStatusCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->name        = 'realtime:status';
        $this->description = 'Report whether the realtime server is configured to deliver anything';
    }

    protected function handle(): int
    {
        $this->section('Realtime (websocket)');

        $problems = 0;

        // ── 1. The runtime ──────────────────────────────────────────────────
        if (class_exists('OpenSwoole\\WebSocket\\Server') || class_exists('Swoole\\WebSocket\\Server')) {
            $this->success('OpenSwoole is loaded, so `realtime:serve` can start.');
        } else {
            $this->error(
                'OpenSwoole is NOT loaded. `realtime:serve` cannot start; add `extension=openswoole` '
                . 'to php.ini. The frame codec and the registry do not need it, which is why the test '
                . 'suite passes without it.',
            );
            ++$problems;
        }

        // ── 2. Origins: the Cross-Site WebSocket Hijacking defence ──────────
        $origins = self::origins();

        if ($origins === []) {
            $this->error(
                'WEBSOCKET_ORIGINS is empty, so EVERY connection is refused. This is the setting that '
                . 'stops a page on another site opening an authenticated socket with a visitor\'s '
                . 'cookies, so it has no permissive default. Set it to your exact origins, '
                . 'e.g. https://app.example.com.',
            );
            ++$problems;
        } else {
            $this->success('Allowed origins: ' . implode(', ', $origins));

            foreach ($origins as $origin) {
                if (!str_starts_with($origin, 'https://')
                    && !str_starts_with($origin, 'http://localhost')
                    && !str_starts_with($origin, 'http://127.0.0.1')) {
                    $this->warning(
                        "  [{$origin}] is not https. A browser will refuse a wss:// socket from an "
                        . 'insecure page, and an ws:// one can be read and rewritten in transit.',
                    );
                }
            }
        }

        if (!self::flag(env('WEBSOCKET_REQUIRE_ORIGIN'), true)) {
            $this->warning(
                'WEBSOCKET_REQUIRE_ORIGIN is false, so a connection with NO Origin header is accepted. '
                . 'Correct for native clients, which must then authenticate by token — and wrong for a '
                . 'browser-only deployment, where it removes the hijacking defence for any client that '
                . 'simply omits the header.',
            );
        }

        // ── 3. The bus ──────────────────────────────────────────────────────
        $this->newLine();
        $this->muted('Bus channel : ' . (trim((string) (env('WEBSOCKET_BUS_CHANNEL') ?? '')) ?: 'hkm.rt.events'));
        $this->muted('Listen      : ' . self::host() . ':' . self::port() . self::path());
        $this->muted('Workers     : ' . self::workers());
        $this->muted('Protocol    : ' . Handshake::VERSION . ' (RFC 6455)');

        // Settings only. Who is online is personal data, and a status command
        // anybody with a shell can run is the wrong place to print it.
        $presence = PresenceSettings::fromEnv();
        $this->muted('Presence    : ' . ($presence->enabled
            ? "on (lease {$presence->ttl}s, typing {$presence->typingTtl}s, sweep every {$presence->sweepInterval}s, max {$presence->maxMembers}/channel)"
            : 'off'));

        // ── 4. What this command CANNOT check ───────────────────────────────
        $this->newLine();
        $this->section('Not checked from here');
        $this->muted(
            'Whether a PubSubPort is bound. It is resolved from the CoreContainer at materialize, so '
            . 'only the bootstrap knows — and without one, ' . NullPubSub::class . ' is used: publishing '
            . 'is a no-op and `realtime:serve` refuses to start rather than hold connections open and '
            . 'deliver nothing.',
        );
        $this->muted(
            'Whether a ChannelAuthorizer is bound. Without one every subscription is refused and the '
            . 'reason is logged per attempt — look for `websocket.authorizer.not_configured`.',
        );
        $this->muted(
            'Whether a CachePort is bound, which presence needs. Without one presence is off — there is no '
            . 'per-worker fallback — and `realtime:serve` says so at start. Who is online is never printed here.',
        );
        $this->muted(
            'Whether the application ever calls Broadcaster::publish(). Nothing in the kernel does it '
            . 'for you: an event reaches a client only because code chose to announce it.',
        );

        $this->newLine();

        if ($problems > 0) {
            $this->error("{$problems} problem(s) would stop this server delivering anything.");

            return 1;
        }

        $this->success('No configuration problem found in what this command can see.');

        return 0;
    }

    /** @return list<string> */
    public static function origins(): array
    {
        $raw = trim((string) (env('WEBSOCKET_ORIGINS') ?? ''));

        if ($raw === '') {
            return [];
        }

        return array_values(array_filter(
            array_map('trim', explode(',', $raw)),
            static fn (string $origin): bool => $origin !== '',
        ));
    }

    public static function host(): string
    {
        return trim((string) (env('WEBSOCKET_HOST') ?? '')) ?: '127.0.0.1';
    }

    public static function port(): int
    {
        return max(1, (int) (env('WEBSOCKET_PORT') ?: 9503));
    }

    public static function path(): string
    {
        $path = trim((string) (env('WEBSOCKET_PATH') ?? '')) ?: '/realtime';

        return str_starts_with($path, '/') ? $path : '/' . $path;
    }

    public static function workers(): int
    {
        return max(1, (int) (env('WEBSOCKET_WORKERS') ?: 2));
    }

    /** `true`/`1`/`yes`/`on` — anything else is false, including a typo. */
    public static function flag(mixed $value, bool $default = false): bool
    {
        $text = strtolower(trim((string) ($value ?? '')));

        if ($text === '') {
            return $default;
        }

        return \in_array($text, ['1', 'true', 'yes', 'on'], true);
    }
}
