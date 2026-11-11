<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Domain\CloseCode;
use Plugins\WebSocket\Domain\Exceptions\ProtocolException;
use Plugins\WebSocket\Domain\Frame;
use Plugins\WebSocket\Domain\Opcode;

/**
 * The RFC 6455 frame codec.
 *
 * THE REFUSALS ARE THE POINT OF THIS FILE
 * ---------------------------------------
 * A round-trip test proves the codec agrees with itself, which is the one thing
 * that was never in doubt. What matters is whether the frames a conforming peer
 * would never send are REFUSED — an unmasked client frame, a non-minimal
 * length, a reserved bit, a fragmented ping — because every one of those is a
 * place where two implementations can be made to disagree about where a frame
 * ends, and that disagreement is the vulnerability.
 *
 * So each refusal below has its own test, and each asserts the CLOSE CODE as
 * well as the fact of the refusal: the code is what a client uses to decide
 * whether to retry, and answering 1002 to an oversized message makes a client
 * reconnect forever.
 */
#[CoversClass(Frame::class)]
#[CoversClass(Opcode::class)]
#[CoversClass(CloseCode::class)]
#[CoversClass(ProtocolException::class)]
final class FrameTest extends TestCase
{
    // ── Round trip, at every length boundary ─────────────────────────────────

    /**
     * The boundaries are where a length encoder is wrong.
     *
     * 125 is the last 7-bit length, 126 the first 16-bit one, 65535 the last,
     * 65536 the first 64-bit one. An off-by-one in any of the three branches
     * shows up at exactly one of these sizes and nowhere else, which is why a
     * single "it round-trips" test with a convenient payload finds nothing.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function lengths(): iterable
    {
        yield 'empty'                 => [0];
        yield 'one byte'              => [1];
        yield 'last 7-bit length'     => [125];
        yield 'first 16-bit length'   => [126];
        yield 'mid 16-bit'            => [1000];
        yield 'last 16-bit length'    => [65535];
        yield 'first 64-bit length'   => [65536];
        yield 'past 64-bit boundary'  => [70000];
    }

    #[DataProvider('lengths')]
    public function test_a_server_frame_round_trips(int $length): void
    {
        $payload = $length > 0 ? random_bytes($length) : '';
        $encoded = Frame::binary($payload)->encode();

        $decoded = Frame::decode($encoded, expectMasked: false);

        self::assertNotNull($decoded, 'a whole frame must decode');
        [$frame, $consumed] = $decoded;

        self::assertSame($length, \strlen($frame->payload));
        self::assertSame($payload, $frame->payload);
        self::assertSame(Opcode::Binary, $frame->opcode);
        self::assertTrue($frame->fin);
        self::assertFalse($frame->masked, 'a server frame is never masked');
        self::assertSame(\strlen($encoded), $consumed, 'the whole frame must be consumed');
    }

    #[DataProvider('lengths')]
    public function test_a_masked_client_frame_round_trips(int $length): void
    {
        $payload = $length > 0 ? random_bytes($length) : '';
        $encoded = self::clientFrame(Opcode::Binary, $payload);

        $decoded = Frame::decode($encoded, expectMasked: true);

        self::assertNotNull($decoded);
        [$frame] = $decoded;

        self::assertSame($payload, $frame->payload, 'unmasking must restore the payload exactly');
        self::assertTrue($frame->masked);
    }

    /** The encoder must use the SHORTEST form, which is what the decoder demands. */
    #[DataProvider('lengths')]
    public function test_the_encoder_uses_the_minimal_length_form(int $length): void
    {
        $encoded = Frame::binary($length === 0 ? '' : str_repeat('x', $length))->encode();
        $second  = \ord($encoded[1]) & 0x7F;

        $expected = match (true) {
            $length <= 125    => $length,
            $length <= 0xFFFF => 126,
            default           => 127,
        };

        self::assertSame($expected, $second, "a {$length}-byte payload used the wrong length form");
    }

    // ── Masking: the rule that is asymmetric ─────────────────────────────────

    /**
     * An unmasked frame from a client is refused.
     *
     * Not pedantry. Masking exists so a sandboxed script cannot author the
     * bytes that appear on a TCP connection — which is what made WebSocket
     * usable through proxies that would otherwise have been poisoned by a
     * payload shaped like an HTTP request. An unmasked client frame is either a
     * broken client or that attack.
     */
    public function test_an_unmasked_client_frame_is_refused(): void
    {
        $unmasked = Frame::text('hello')->encode();

        $this->assertRefused(
            CloseCode::ProtocolError,
            'not masked',
            static fn () => Frame::decode($unmasked, expectMasked: true),
        );
    }

    /** And a masked frame from a server, which some clients drop the connection over. */
    public function test_a_masked_server_frame_is_refused(): void
    {
        $masked = self::clientFrame(Opcode::Text, 'hello');

        $this->assertRefused(
            CloseCode::ProtocolError,
            'is masked',
            static fn () => Frame::decode($masked, expectMasked: false),
        );
    }

    // ── Non-minimal lengths: the smuggling vector ────────────────────────────

    /**
     * A 5-byte payload declared in 16 bits is refused.
     *
     * Three encodings of one number is three chances for a proxy and a server
     * to read the same bytes as different frames. Being lenient here is the
     * same mistake, reached the same way, as the Content-Length handling that
     * makes HTTP request smuggling possible.
     */
    public function test_a_non_minimal_16_bit_length_is_refused(): void
    {
        // FIN|binary, masked, length 126, then a 16-bit 5.
        $bytes = "\x82\xFE" . pack('n', 5) . "\x00\x00\x00\x00" . 'hello';

        $this->assertRefused(
            CloseCode::ProtocolError,
            'the 7-bit form was required',
            static fn () => Frame::decode($bytes, expectMasked: true),
        );
    }

    public function test_a_non_minimal_64_bit_length_is_refused(): void
    {
        $bytes = "\x82\xFF" . pack('J', 5) . "\x00\x00\x00\x00" . 'hello';

        $this->assertRefused(
            CloseCode::ProtocolError,
            'a shorter form was required',
            static fn () => Frame::decode($bytes, expectMasked: true),
        );
    }

    /**
     * A 64-bit length with its high bit set is refused.
     *
     * `unpack('J')` cannot represent it, so PHP hands back a NEGATIVE integer —
     * and a negative length makes every `available < offset + length` check
     * below it pass. Without this guard that is an out-of-bounds read reached
     * from eight attacker-chosen bytes.
     */
    public function test_a_64_bit_length_with_the_high_bit_set_is_refused(): void
    {
        $bytes = "\x82\xFF" . str_repeat("\xFF", 8) . "\x00\x00\x00\x00";

        $this->assertRefused(
            CloseCode::ProtocolError,
            'high bit set',
            static fn () => Frame::decode($bytes, expectMasked: true),
        );
    }

    // ── Reserved bits and opcodes ────────────────────────────────────────────

    /**
     * A set RSV bit is refused because no extension was negotiated.
     *
     * RSV1 is what `permessage-deflate` sets. A server that ignores it reads a
     * DEFLATE stream as though it were the payload — so every length and every
     * UTF-8 check afterwards is applied to the wrong bytes.
     */
    public function test_a_reserved_bit_is_refused(): void
    {
        foreach ([0x40, 0x20, 0x10] as $rsv) {
            $bytes = \chr(0x80 | $rsv | 0x01) . "\x80" . "\x00\x00\x00\x00";

            $this->assertRefused(
                CloseCode::ProtocolError,
                'reserved bit',
                static fn () => Frame::decode($bytes, expectMasked: true),
            );
        }
    }

    /** @return iterable<string, array{0: int}> */
    public static function reservedOpcodes(): iterable
    {
        foreach ([0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] as $opcode) {
            yield 'opcode 0x' . dechex($opcode) => [$opcode];
        }
    }

    #[DataProvider('reservedOpcodes')]
    public function test_a_reserved_opcode_is_refused(int $opcode): void
    {
        $bytes = \chr((0x80 | $opcode) & 0xFF) . "\x80" . "\x00\x00\x00\x00";

        $this->assertRefused(
            CloseCode::ProtocolError,
            'reserved opcode',
            static fn () => Frame::decode($bytes, expectMasked: true),
        );
    }

    // ── Control frames ──────────────────────────────────────────────────────

    /**
     * A fragmented control frame is refused.
     *
     * A ping must be deliverable BETWEEN the fragments of a large message; one
     * that could itself be fragmented could not serve as a keepalive.
     */
    public function test_a_fragmented_control_frame_is_refused(): void
    {
        $bytes = "\x09\x80" . "\x00\x00\x00\x00";   // ping with FIN clear

        $this->assertRefused(
            CloseCode::ProtocolError,
            'is fragmented',
            static fn () => Frame::decode($bytes, expectMasked: true),
        );
    }

    /**
     * A control frame over 125 bytes is refused — and refused from the HEADER,
     * before the body is read.
     *
     * Otherwise a peer can open a connection and declare a two-gigabyte ping,
     * and a server that buffers it in order to echo a matching pong has been
     * told how much memory to allocate by an unauthenticated client.
     */
    public function test_an_oversized_control_frame_is_refused(): void
    {
        $bytes = "\x89\xFE" . pack('n', 126) . "\x00\x00\x00\x00";

        $this->assertRefused(
            CloseCode::ProtocolError,
            'more than 125',
            static fn () => Frame::decode($bytes, expectMasked: true),
        );
    }

    /** The encoder refuses it too, so the server cannot emit one by mistake. */
    public function test_encoding_an_oversized_control_frame_is_refused(): void
    {
        $this->assertRefused(
            CloseCode::ProtocolError,
            'control frame may carry at most',
            static fn () => Frame::ping(str_repeat('x', 126))->encode(),
        );
    }

    // ── Payload limits ──────────────────────────────────────────────────────

    /**
     * An over-limit frame is refused from its header, with 1009 and not 1002.
     *
     * The code is the difference between a client that stops sending oversized
     * messages and one that reconnects in a loop, because 1002 tells it the
     * connection was broken rather than that its message was.
     */
    public function test_a_frame_over_the_limit_is_refused_before_its_body(): void
    {
        $bytes = "\x82\xFF" . pack('J', 10_000_000) . "\x00\x00\x00\x00";

        self::assertSame(14, \strlen($bytes), 'the header alone, with no payload behind it');

        $this->assertRefused(
            CloseCode::TooLarge,
            'over this server',
            static fn () => Frame::decode($bytes, expectMasked: true, maxPayload: 1024),
        );
    }

    // ── Partial frames are not errors ───────────────────────────────────────

    /**
     * Every prefix of a valid frame decodes to null, not an exception.
     *
     * TCP delivers bytes, not frames, so a half-arrived frame is the ordinary
     * case. A codec that threw on a short buffer would make the server drop
     * connections under exactly the conditions it is meant to handle — a large
     * message, or a slow client.
     */
    public function test_every_prefix_of_a_frame_decodes_to_null(): void
    {
        $whole = self::clientFrame(Opcode::Binary, random_bytes(70_000));

        foreach ([1, 2, 3, 9, 10, 13, 14, 100, 69_999, \strlen($whole) - 1] as $take) {
            self::assertNull(
                Frame::decode(substr($whole, 0, $take), expectMasked: true),
                "a {$take}-byte prefix must be reported as incomplete, not rejected",
            );
        }

        self::assertNotNull(Frame::decode($whole, expectMasked: true));
    }

    /** Trailing bytes belong to the next frame and must not be consumed. */
    public function test_decoding_stops_at_the_end_of_the_first_frame(): void
    {
        $first  = self::clientFrame(Opcode::Text, 'one');
        $second = self::clientFrame(Opcode::Text, 'two');

        $decoded = Frame::decode($first . $second, expectMasked: true);

        self::assertNotNull($decoded);
        [$frame, $consumed] = $decoded;

        self::assertSame('one', $frame->payload);
        self::assertSame(\strlen($first), $consumed, 'the second frame must be left in the buffer');
    }

    // ── Close frames ────────────────────────────────────────────────────────

    public function test_a_close_frame_carries_its_code_and_reason(): void
    {
        $encoded = Frame::close(CloseCode::PolicyViolation, 'not allowed')->encode();
        $decoded = Frame::decode($encoded, expectMasked: false);

        self::assertNotNull($decoded);
        [$frame] = $decoded;

        self::assertSame(1008, $frame->closeCode());
        self::assertSame('not allowed', $frame->closeReason());
    }

    /** An empty close frame states no code, which is legal. */
    public function test_an_empty_close_frame_states_no_code(): void
    {
        $frame = new Frame(Opcode::Close, '');

        self::assertNull($frame->closeCode());
    }

    /** One byte is half a status code, and the other half cannot be guessed. */
    public function test_a_one_byte_close_frame_is_refused(): void
    {
        $frame = new Frame(Opcode::Close, "\x03");

        $this->assertRefused(CloseCode::ProtocolError, 'a status code needs two', $frame->closeCode(...));
    }

    /**
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function closeCodes(): iterable
    {
        yield '1000 normal'            => [1000, true];
        yield '1001 going away'        => [1001, true];
        yield '1011 server error'      => [1011, true];
        yield '3000 library range'     => [3000, true];
        yield '4000 application range' => [4000, true];
        yield '4999 application range' => [4999, true];

        // Local-only: each describes something that happened INSTEAD of a close
        // frame, so receiving one in a close frame is a contradiction.
        yield '1005 no status (local only)'   => [1005, false];
        yield '1006 abnormal (local only)'    => [1006, false];
        yield '1015 tls failure (local only)' => [1015, false];

        // Unassigned and reserved: neither end agrees what they mean.
        yield '1004 unassigned'  => [1004, false];
        yield '1012 unassigned'  => [1012, false];
        yield '1014 unassigned'  => [1014, false];
        yield '999 below range'  => [999, false];
        yield '2000 reserved'    => [2000, false];
        yield '5000 above range' => [5000, false];
    }

    #[DataProvider('closeCodes')]
    public function test_close_code_validity_on_the_wire(int $code, bool $valid): void
    {
        self::assertSame($valid, CloseCode::isValidOnTheWire($code));
    }

    #[DataProvider('closeCodes')]
    public function test_an_invalid_close_code_is_refused_when_received(int $code, bool $valid): void
    {
        $frame = new Frame(Opcode::Close, pack('n', $code));

        if ($valid) {
            self::assertSame($code, $frame->closeCode());

            return;
        }

        $this->assertRefused(CloseCode::ProtocolError, 'not valid on the wire', $frame->closeCode(...));
    }

    /**
     * A long reason is truncated on a CHARACTER boundary.
     *
     * `substr($reason, 0, 123)` can cut a multi-byte character in half, which
     * makes the close frame's payload invalid UTF-8 — so the peer answers a
     * close frame with a 1007 protocol error, and the orderly shutdown becomes
     * a failure, for the sake of a message nobody reads.
     */
    public function test_a_long_close_reason_is_truncated_without_breaking_a_character(): void
    {
        // 'é' is two bytes, so 70 of them is 140 — past the 123-byte ceiling,
        // and the cut lands in the middle of one.
        $frame  = Frame::close(CloseCode::Normal, str_repeat('é', 70));
        $reason = $frame->closeReason();

        self::assertLessThanOrEqual(Frame::MAX_CLOSE_REASON, \strlen($reason));
        self::assertTrue(mb_check_encoding($reason, 'UTF-8'), 'the truncated reason must still be valid UTF-8');
        self::assertLessThanOrEqual(125, \strlen($frame->payload), 'the whole payload must fit a control frame');

        // And it must survive a round trip rather than being refused by our own decoder.
        $decoded = Frame::decode($frame->encode(), expectMasked: false);
        self::assertNotNull($decoded);
        self::assertSame(1000, $decoded[0]->closeCode());
    }

    /** A close reason that is not UTF-8 is refused with 1007, not 1002. */
    public function test_a_close_reason_that_is_not_utf8_is_refused(): void
    {
        $frame = new Frame(Opcode::Close, pack('n', 1000) . "\xC3\x28");

        $this->assertRefused(CloseCode::BadPayload, 'not valid UTF-8', $frame->closeCode(...));
    }

    // ── Text payload encoding ───────────────────────────────────────────────

    public function test_invalid_utf8_in_a_text_message_is_refused(): void
    {
        $this->assertRefused(
            CloseCode::BadPayload,
            'not valid UTF-8',
            static fn () => Frame::assertUtf8("\xC3\x28"),
        );
    }

    public function test_valid_utf8_passes(): void
    {
        // Asserting on the INPUT rather than `assertTrue(true)`: the property
        // is that every one of these is accepted, including the multi-byte and
        // 4-byte sequences a naive byte-wise validator rejects.
        $accepted = 0;

        foreach (['', 'plain', 'héllo wörld 🌍', "\u{10FFFF}", 'Ωмир文'] as $valid) {
            Frame::assertUtf8($valid);
            ++$accepted;
        }

        self::assertSame(5, $accepted, 'every valid string must pass the check');
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Build a frame the way a CLIENT would: masked, minimal length.
     *
     * Written here rather than reusing Frame::encode() so the tests are not
     * checking the codec against itself — the masking path in particular has no
     * encoder in the production class at all, because a server never masks.
     */
    private static function clientFrame(Opcode $opcode, string $payload, bool $fin = true): string
    {
        $mask   = random_bytes(4);
        $length = \strlen($payload);

        $header = match (true) {
            $length <= 125    => \chr($length | 0x80),
            $length <= 0xFFFF => \chr(126 | 0x80) . pack('n', $length),
            default           => \chr(127 | 0x80) . pack('J', $length),
        };

        $masked = '';

        for ($i = 0; $i < $length; ++$i) {
            $masked .= $payload[$i] ^ $mask[$i % 4];
        }

        return \chr(($fin ? 0x80 : 0x00) | $opcode->value) . $header . $mask . $masked;
    }

    /**
     * @param \Closure(): mixed $work
     */
    private function assertRefused(CloseCode $expected, string $fragment, \Closure $work): void
    {
        try {
            $work();
            self::fail("expected a refusal mentioning [{$fragment}]");
        } catch (ProtocolException $e) {
            self::assertStringContainsString($fragment, $e->getMessage());
            self::assertSame(
                $expected,
                $e->closeCode,
                "the close code must be {$expected->value}, not {$e->closeCode->value}",
            );
        }
    }
}
