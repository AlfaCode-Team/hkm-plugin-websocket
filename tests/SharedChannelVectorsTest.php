<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Domain\Channel;

/**
 * The channel rules, from the file the Go edge's tests read too.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * There are two implementations of one rule set: {@see Channel} here, and
 * `edge/internal/channel` in Go. The duplication is deliberate — the edge has
 * to refuse a malformed name BEFORE spending a NATS round trip asking this
 * application about it, because otherwise an unauthenticated client decides how
 * much work the application does, which is a denial-of-service primitive.
 *
 * Deliberate or not, two implementations of a security rule drift, and the drift
 * is silent: the stricter one refuses what the other allows, and whichever side
 * a deployment happens to run decides what is reachable.
 *
 * So both suites read `shared/channel-vectors.json`. A rule changed on one side
 * and not the other fails here or in `go test ./internal/channel/` — not in
 * production.
 *
 * ADDING A RULE: put the vector in the shared file FIRST, watch both suites
 * fail, then change both implementations.
 */
#[CoversClass(Channel::class)]
final class SharedChannelVectorsTest extends TestCase
{
    private const VECTORS = __DIR__ . '/../shared/channel-vectors.json';

    /** @return array{valid: list<string>, normalises: array<string, string>, invalid: list<string>} */
    private static function vectors(): array
    {
        $raw = @file_get_contents(self::VECTORS);

        self::assertIsString(
            $raw,
            'shared/channel-vectors.json is missing. It is not optional: without it the PHP and Go '
            . 'channel rules drift silently.',
        );

        $decoded = json_decode($raw, true);

        self::assertIsArray($decoded, 'the shared vectors are not valid JSON');
        self::assertNotEmpty($decoded['valid'] ?? [], 'the shared vectors are empty, so this test proves nothing');
        self::assertNotEmpty($decoded['invalid'] ?? []);

        /** @var array{valid: list<string>, normalises: array<string, string>, invalid: list<string>} $decoded */
        return $decoded;
    }

    public function test_every_shared_valid_name_is_accepted_unchanged(): void
    {
        foreach (self::vectors()['valid'] as $name) {
            $channel = Channel::parse($name);

            self::assertNotNull($channel, "[{$name}] is listed as valid in the shared vectors");
            self::assertSame($name, $channel->name, 'a valid name must come back unchanged');
        }
    }

    public function test_every_shared_normalising_name_trims_to_the_expected_value(): void
    {
        foreach (self::vectors()['normalises'] as $raw => $expected) {
            $channel = Channel::parse((string) $raw);

            self::assertNotNull($channel, 'the shared vectors say [' . addcslashes((string) $raw, "\0..\37") . '] normalises');
            self::assertSame($expected, $channel->name);
        }
    }

    public function test_every_shared_invalid_name_is_refused(): void
    {
        foreach (self::vectors()['invalid'] as $name) {
            self::assertNull(
                Channel::parse($name),
                '[' . addcslashes($name, "\0..\37") . '] is listed as INVALID in the shared vectors',
            );
        }
    }

    /**
     * Every control byte, which JSON cannot carry in the shared file.
     *
     * NUL is the one that matters, and it is the one PHP's default `trim()`
     * silently repaired: `"documents.42\0"` lost its NUL and was accepted as
     * the perfectly valid channel `documents.42`. The Go side cannot have that
     * bug, so without this test the two would differ on exactly the input most
     * likely to be a probe.
     */
    public function test_every_control_byte_is_refused_on_both_sides(): void
    {
        for ($byte = 0x00; $byte <= 0x1F; ++$byte) {
            self::assertNull(
                Channel::parse('documents.' . \chr($byte) . '42'),
                \sprintf('byte 0x%02X must be refused', $byte),
            );
        }

        self::assertNull(Channel::parse("documents.\x7F42"), 'DEL must be refused');
        self::assertNull(Channel::parse("documents.42\x00"), 'a trailing NUL must not be trimmed into a valid name');
    }

    public function test_the_length_limit_matches_the_go_side(): void
    {
        $atLimit = str_repeat('a', Channel::MAX_LENGTH);

        self::assertSame(128, Channel::MAX_LENGTH, 'both implementations hardcode 128');
        self::assertNotNull(Channel::parse($atLimit));
        self::assertNull(Channel::parse(str_repeat('a', Channel::MAX_LENGTH + 1)));

        // Applied AFTER trimming on both sides, so padding must not make a
        // usable name unusable.
        self::assertSame($atLimit, Channel::parse('  ' . $atLimit . '  ')?->name);
    }
}
