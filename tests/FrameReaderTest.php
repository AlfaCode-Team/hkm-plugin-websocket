<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Domain\CloseCode;
use Plugins\WebSocket\Domain\Exceptions\ProtocolException;
use Plugins\WebSocket\Domain\FrameReader;
use Plugins\WebSocket\Domain\Message;
use Plugins\WebSocket\Domain\Opcode;

/**
 * Reassembly: bytes to frames to messages.
 *
 * THE BYTE-AT-A-TIME TEST IS THE ONE THAT MATTERS MOST
 * ----------------------------------------------------
 * {@see self::test_a_message_arrives_correctly_one_byte_at_a_time()} feeds the
 * reader a single byte at a time, which is the hardest schedule TCP can produce
 * and the one a developer never sees locally — on loopback the whole message
 * arrives in one `recv()`, so a reader that only works when frames arrive whole
 * passes every manual test and fails in production under load.
 *
 * Everything else here is a fragmentation rule, and each one has a failure that
 * is silent rather than loud: a message spliced together from two senders'
 * frames, a ping that corrupts the message it was sent inside, a buffer that
 * grows until the worker dies.
 */
#[CoversClass(FrameReader::class)]
#[CoversClass(Message::class)]
final class FrameReaderTest extends TestCase
{
    public function test_a_single_whole_frame_becomes_one_message(): void
    {
        $reader = new FrameReader();
        $reader->feed(self::clientFrame(Opcode::Text, 'hello'));

        $messages = $reader->drain();

        self::assertCount(1, $messages);
        self::assertSame('hello', $messages[0]->payload);
        self::assertTrue($messages[0]->isText());
    }

    /** Several frames in one read are all returned, in order. */
    public function test_several_frames_in_one_read_are_all_returned(): void
    {
        $reader = new FrameReader();
        $reader->feed(
            self::clientFrame(Opcode::Text, 'one')
            . self::clientFrame(Opcode::Text, 'two')
            . self::clientFrame(Opcode::Text, 'three'),
        );

        self::assertSame(
            ['one', 'two', 'three'],
            array_map(static fn (Message $m): string => $m->payload, $reader->drain()),
        );
    }

    /**
     * One byte at a time. See the class docblock.
     *
     * Uses a payload past the 16-bit boundary so the extended length field is
     * also split across feeds — the header itself arrives in pieces, which is
     * the case a reader that assumes it can read two bytes gets wrong.
     */
    public function test_a_message_arrives_correctly_one_byte_at_a_time(): void
    {
        $payload = random_bytes(70_000);
        $bytes   = self::clientFrame(Opcode::Binary, $payload);
        $reader  = new FrameReader();

        $collected = [];

        for ($i = 0, $length = \strlen($bytes); $i < $length; ++$i) {
            $reader->feed($bytes[$i]);

            foreach ($reader->drain() as $message) {
                $collected[] = $message;
            }
        }

        self::assertCount(1, $collected, 'exactly one message, delivered only once it was whole');
        self::assertSame($payload, $collected[0]->payload);
    }

    // ── Fragmentation ───────────────────────────────────────────────────────

    public function test_a_fragmented_message_is_reassembled(): void
    {
        $reader = new FrameReader();

        $reader->feed(self::clientFrame(Opcode::Text, 'Hel', fin: false));
        self::assertSame([], $reader->drain(), 'nothing is delivered until FIN');

        $reader->feed(self::clientFrame(Opcode::Continuation, 'lo, ', fin: false));
        self::assertSame([], $reader->drain());

        $reader->feed(self::clientFrame(Opcode::Continuation, 'world'));
        $messages = $reader->drain();

        self::assertCount(1, $messages);
        self::assertSame('Hello, world', $messages[0]->payload);
        self::assertSame(Opcode::Text, $messages[0]->opcode, 'the message keeps the FIRST frame\'s type');
    }

    /**
     * A ping between two fragments is answered, and does not join the message.
     *
     * Required by the specification, and the reason control frames bypass
     * reassembly. A reader that routed the ping into the fragment buffer would
     * insert its own keepalive payload into the middle of the user's message —
     * corruption caused entirely by the server.
     */
    public function test_a_control_frame_between_fragments_does_not_corrupt_the_message(): void
    {
        $reader = new FrameReader();

        $reader->feed(self::clientFrame(Opcode::Text, 'abc', fin: false));
        $reader->feed(self::clientFrame(Opcode::Ping, 'keepalive'));
        $reader->feed(self::clientFrame(Opcode::Continuation, 'def'));

        $messages = $reader->drain();

        self::assertCount(2, $messages);

        self::assertTrue($messages[0]->isControl(), 'the ping is delivered immediately, not queued');
        self::assertSame(Opcode::Ping, $messages[0]->opcode);
        self::assertSame('keepalive', $messages[0]->payload);

        self::assertSame('abcdef', $messages[1]->payload, 'the ping must not appear in the message');
    }

    /**
     * A continuation with nothing open is refused.
     *
     * In a reader that simply appends, this frame lands on whatever the
     * PREVIOUS message left behind — so a peer can prepend chosen bytes to
     * somebody else's message, or resurrect a buffer that was already
     * delivered.
     */
    public function test_a_continuation_with_no_message_open_is_refused(): void
    {
        $reader = new FrameReader();
        $reader->feed(self::clientFrame(Opcode::Continuation, 'orphan'));

        $this->assertRefused(CloseCode::ProtocolError, 'no message open', $reader->drain(...));
    }

    /**
     * A new data frame while a message is open is refused.
     *
     * Not treated as a fresh start: either reading is defensible, and splicing
     * the two together is the one that cannot be detected downstream — the
     * application receives one message containing both halves and has no way
     * to know it was two.
     */
    public function test_a_new_data_frame_interrupting_a_fragmented_message_is_refused(): void
    {
        $reader = new FrameReader();
        $reader->feed(self::clientFrame(Opcode::Text, 'first half', fin: false));
        $reader->feed(self::clientFrame(Opcode::Text, 'interrupting'));

        $this->assertRefused(CloseCode::ProtocolError, 'still open', $reader->drain(...));
    }

    /**
     * A multi-byte character split across a fragment boundary is accepted.
     *
     * The reason UTF-8 is checked on the whole message and never per fragment.
     * A per-fragment check rejects this — a legitimate message, split the way a
     * client's buffer happened to fall — and only for messages large enough to
     * be fragmented, so never in development.
     */
    public function test_a_character_split_across_fragments_is_accepted(): void
    {
        // 'é' is 0xC3 0xA9. One byte in each fragment.
        $reader = new FrameReader();
        $reader->feed(self::clientFrame(Opcode::Text, "caf\xC3", fin: false));
        $reader->feed(self::clientFrame(Opcode::Continuation, "\xA9"));

        $messages = $reader->drain();

        self::assertCount(1, $messages);
        self::assertSame('café', $messages[0]->payload);
    }

    /** But a genuinely broken sequence is still refused, with 1007. */
    public function test_invalid_utf8_across_fragments_is_refused(): void
    {
        $reader = new FrameReader();
        $reader->feed(self::clientFrame(Opcode::Text, "\xC3", fin: false));
        $reader->feed(self::clientFrame(Opcode::Continuation, "\x28"));

        $this->assertRefused(CloseCode::BadPayload, 'not valid UTF-8', $reader->drain(...));
    }

    /** A binary message is never UTF-8 checked — arbitrary bytes are the point. */
    public function test_a_binary_message_may_hold_any_bytes(): void
    {
        $payload = "\xC3\x28\xFF\x00\xFE";
        $reader  = new FrameReader();
        $reader->feed(self::clientFrame(Opcode::Binary, $payload));

        $messages = $reader->drain();

        self::assertCount(1, $messages);
        self::assertSame($payload, $messages[0]->payload);
    }

    // ── The two size limits, which are different numbers ────────────────────

    /** One oversized frame is refused from its header. */
    public function test_a_frame_over_the_frame_limit_is_refused(): void
    {
        $reader = new FrameReader(maxPayload: 100);
        $reader->feed(self::clientFrame(Opcode::Binary, random_bytes(200)));

        $this->assertRefused(CloseCode::TooLarge, 'over this server', $reader->drain(...));
    }

    /**
     * And a fragmented message whose SUM exceeds the message limit.
     *
     * The case a per-frame limit does not cover, and the one that kills a
     * worker: every fragment is comfortably under `maxPayload`, FIN never
     * arrives, and without `maxMessage` the buffer grows until the process is
     * killed. A peer sends 1-byte fragments forever and nothing fires.
     */
    public function test_fragments_summing_over_the_message_limit_are_refused(): void
    {
        $reader = new FrameReader(maxPayload: 1024, maxMessage: 2048);

        // The FIRST frame opens the message; the rest must be continuations.
        // Writing them all as Binary is a different error — an interrupted
        // message — and the reader says so, which is how this fixture was
        // caught being wrong about its own scenario rather than the limit
        // being wrong.
        $reader->feed(self::clientFrame(Opcode::Binary, str_repeat('x', 1000), fin: false));

        for ($i = 0; $i < 2; ++$i) {
            $reader->feed(self::clientFrame(Opcode::Continuation, str_repeat('x', 1000), fin: false));
        }

        $this->assertRefused(CloseCode::TooLarge, 'fragmented message reached', $reader->drain(...));
    }

    /**
     * After an over-limit message is refused, the reader holds nothing.
     *
     * Otherwise the rejected half-message prepends itself to whatever arrives
     * next — and the caller may legitimately keep the reader, since a test or a
     * lenient server might choose not to close the connection.
     */
    public function test_a_refused_message_leaves_no_residue(): void
    {
        $reader = new FrameReader(maxPayload: 1024, maxMessage: 1500);

        $reader->feed(self::clientFrame(Opcode::Binary, str_repeat('x', 1000), fin: false));
        $reader->feed(self::clientFrame(Opcode::Continuation, str_repeat('y', 1000)));

        try {
            $reader->drain();
            self::fail('expected a refusal');
        } catch (ProtocolException) {
            // expected
        }

        $reader->feed(self::clientFrame(Opcode::Text, 'fresh'));
        $messages = $reader->drain();

        self::assertCount(1, $messages);
        self::assertSame('fresh', $messages[0]->payload, 'the rejected bytes must not be prepended');
    }

    // ── JSON decoding of a text message ─────────────────────────────────────

    public function test_a_json_object_payload_decodes(): void
    {
        $message = Message::data(Opcode::Text, '{"type":"subscribe","channels":["documents.42"]}');

        self::assertSame(
            ['type' => 'subscribe', 'channels' => ['documents.42']],
            $message->json(),
        );
    }

    /**
     * Anything that is not a JSON OBJECT decodes to null.
     *
     * A JSON array would decode to a PHP list, on which `$payload['type']` is
     * silently null — indistinguishable from an object that omitted the field,
     * so a malformed message would be handled as a valid one with a missing
     * key.
     *
     * The depth limit is the other half: a deeply nested document is the cheap
     * way to make a JSON parser recurse, and this runs on the first bytes an
     * unauthenticated client sends.
     */
    public function test_a_payload_that_is_not_a_json_object_decodes_to_null(): void
    {
        foreach ([
            'a json array'      => '["subscribe"]',
            'a bare string'     => '"subscribe"',
            'a number'          => '42',
            'null'              => 'null',
            'malformed json'    => '{"type":',
            'empty'             => '',
            'deeply nested'     => str_repeat('[', 40) . str_repeat(']', 40),
        ] as $label => $payload) {
            self::assertNull(
                Message::data(Opcode::Text, $payload)->json(),
                "[{$label}] should not decode to an object",
            );
        }
    }

    /** A binary message is never JSON, whatever its bytes say. */
    public function test_a_binary_message_never_decodes_as_json(): void
    {
        self::assertNull(Message::data(Opcode::Binary, '{"type":"subscribe"}')->json());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /** A masked client frame, built independently of Frame::encode(). */
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

    /** @param \Closure(): mixed $work */
    private function assertRefused(CloseCode $expected, string $fragment, \Closure $work): void
    {
        try {
            $work();
            self::fail("expected a refusal mentioning [{$fragment}]");
        } catch (ProtocolException $e) {
            self::assertStringContainsString($fragment, $e->getMessage());
            self::assertSame($expected, $e->closeCode);
        }
    }
}
