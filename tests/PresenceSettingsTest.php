<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Application\Services\PresenceSettings;

#[CoversClass(PresenceSettings::class)]
final class PresenceSettingsTest extends TestCase
{
    private const KEYS = [
        'WEBSOCKET_PRESENCE', 'WEBSOCKET_PRESENCE_TTL', 'WEBSOCKET_PRESENCE_TYPING_TTL',
        'WEBSOCKET_PRESENCE_SWEEP_INTERVAL', 'WEBSOCKET_PRESENCE_MAX_MEMBERS',
    ];

    protected function setUp(): void
    {
        $this->clean();
    }

    protected function tearDown(): void
    {
        $this->clean();
    }

    public function test_the_defaults_match_the_manifest(): void
    {
        $s = PresenceSettings::fromEnv();

        self::assertTrue($s->enabled);
        self::assertSame([45, 6, 10, 500], [$s->ttl, $s->typingTtl, $s->sweepInterval, $s->maxMembers]);
        self::assertSame(15, $s->heartbeatInterval());
    }

    public function test_the_environment_is_read(): void
    {
        $_ENV['WEBSOCKET_PRESENCE']                = 'off';
        $_ENV['WEBSOCKET_PRESENCE_TTL']            = '90';
        $_ENV['WEBSOCKET_PRESENCE_TYPING_TTL']     = '4';
        $_ENV['WEBSOCKET_PRESENCE_SWEEP_INTERVAL'] = '20';
        $_ENV['WEBSOCKET_PRESENCE_MAX_MEMBERS']    = '10';

        $s = PresenceSettings::fromEnv();

        self::assertFalse($s->enabled);
        self::assertSame([90, 4, 20, 10], [$s->ttl, $s->typingTtl, $s->sweepInterval, $s->maxMembers]);
        self::assertSame(30, $s->heartbeatInterval());
    }

    /** A typo disables a feature that publishes who is online; it does not enable it. */
    public function test_an_unrecognised_enabled_value_is_off(): void
    {
        $_ENV['WEBSOCKET_PRESENCE'] = 'ture';

        self::assertFalse(PresenceSettings::fromEnv()->enabled);
    }

    public function test_nonsense_numbers_are_clamped_not_trusted(): void
    {
        $s = new PresenceSettings(ttl: 0, typingTtl: 999, sweepInterval: 0, maxMembers: -5);

        self::assertGreaterThanOrEqual(9, $s->ttl);
        self::assertLessThanOrEqual($s->ttl, $s->typingTtl, 'typing must not outlive the lease');
        self::assertGreaterThanOrEqual(2, $s->sweepInterval);
        self::assertSame(1, $s->maxMembers);
        self::assertGreaterThanOrEqual(3, $s->heartbeatInterval());
    }

    private function clean(): void
    {
        foreach (self::KEYS as $key) {
            unset($_ENV[$key], $_SERVER[$key]);
        }
    }
}
