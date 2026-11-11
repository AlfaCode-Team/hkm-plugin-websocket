<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

use Plugins\WebSocket\Domain\Exceptions\ProtocolException;

/**
 * One RFC 6455 frame, decoded from bytes or encoded to them.
 *
 * ```
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-------+-+-------------+-------------------------------+
 * |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 * |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 * |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 * | |1|2|3|       |K|             |                               |
 * +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 * |     Extended payload length continued, if payload len == 127  |
 * + - - - - - - - - - - - - - - - +-------------------------------+
 * |                               |Masking-key, if MASK set to 1  |
 * +-------------------------------+-------------------------------+
 * |    Masking-key (continued)    |          Payload Data         |
 * +-------------------------------- - - - - - - - - - - - - - - - +
 * ```
 *
 * MASKING IS NOT ENCRYPTION AND REFUSING AN UNMASKED CLIENT FRAME IS NOT
 * PEDANTRY
 * ---------------------------------------------------------------------------
 * The mask is four random bytes XORed over the payload, sent in the clear right
 * next to it, so it hides nothing from anyone watching. It exists for one
 * reason: to stop a browser being used to write ATTACKER-CHOSEN BYTES onto a
 * TCP connection that an intermediary might interpret as a new request.
 *
 * Before masking existed, a page could open a WebSocket through a transparent
 * proxy and send a payload that was itself a valid HTTP request — `GET
 * /victim.js HTTP/1.1` and so on. A proxy that did not understand the upgrade
 * saw a second request on a connection it was pooling and cached the response
 * under the attacker's chosen URL, poisoning it for every other user behind
 * that proxy. Masking makes the bytes on the wire unpredictable to the script,
 * so it cannot author them.
 *
 * All of which means the rule is asymmetric and both halves matter:
 *
 *   - a frame FROM a client MUST be masked. An unmasked one is either a
 *     non-conforming client or an attempt to do the above, and RFC 6455 says to
 *     close with 1002 rather than process it;
 *   - a frame FROM a server MUST NOT be masked. A masked server frame makes
 *     some clients close the connection, and it buys nothing: a server is not
 *     a sandboxed script that an attacker controls.
 *
 * LENGTHS MUST BE MINIMAL, and this is the parser-disagreement vector
 * -------------------------------------------------------------------
 * A 5-byte payload can be encoded three ways: as 5 in the 7-bit field, as 126
 * followed by a 16-bit 5, or as 127 followed by a 64-bit 5. The specification
 * requires the shortest, and this class REFUSES the others.
 *
 * Accepting them would be the generous choice and the wrong one. The whole value
 * of a length check is that every implementation in the chain agrees where the
 * frame ends; the moment two encodings of one number are both acceptable, a
 * proxy and a server can read the same bytes as different frames. That is the
 * same class of bug as HTTP request smuggling, reached the same way — by being
 * lenient about a redundant encoding.
 */
final readonly class Frame
{
    /** A control frame's payload ceiling, from the specification. */
    public const MAX_CONTROL_PAYLOAD = 125;

    /** A close frame's reason, after the two status bytes. */
    public const MAX_CLOSE_REASON = 123;

    private const MASK_BYTES = 4;

    public function __construct(
        public Opcode $opcode,
        public string $payload = '',
        /** False marks a fragment with more to come. */
        public bool $fin = true,
        /** Set on frames read from a client; never set on frames this server sends. */
        public bool $masked = false,
    ) {}

    // ── Constructors for the frames a server sends ───────────────────────────

    public static function text(string $payload): self
    {
        return new self(Opcode::Text, $payload);
    }

    public static function binary(string $payload): self
    {
        return new self(Opcode::Binary, $payload);
    }

    public static function ping(string $payload = ''): self
    {
        return new self(Opcode::Ping, $payload);
    }

    public static function pong(string $payload = ''): self
    {
        return new self(Opcode::Pong, $payload);
    }

    /**
     * A close frame.
     *
     * The reason is TRUNCATED rather than rejected, and truncated on a
     * character boundary rather than a byte one. A close frame's payload is at
     * most 125 bytes of which two are the code, so a reason longer than 123
     * bytes cannot be sent — and the obvious `substr($reason, 0, 123)` can cut
     * a multi-byte character in half, which makes the payload invalid UTF-8 and
     * earns a 1007 from the peer in reply to a close frame. The connection then
     * ends on a protocol error instead of the orderly shutdown that was
     * intended, for the sake of a message nobody reads.
     */
    public static function close(CloseCode $code = CloseCode::Normal, string $reason = ''): self
    {
        $trimmed = mb_strcut($reason, 0, self::MAX_CLOSE_REASON, 'UTF-8');

        return new self(Opcode::Close, pack('n', $code->value) . $trimmed);
    }

    // ── The wire format ──────────────────────────────────────────────────────

    /**
     * This frame as bytes, unmasked, for a server to write.
     *
     * Never emits a mask. See the class docblock for why that is a rule rather
     * than an omission.
     */
    public function encode(): string
    {
        $length = \strlen($this->payload);

        if ($this->opcode->isControl() && $length > self::MAX_CONTROL_PAYLOAD) {
            throw ProtocolException::framing(
                "A {$this->opcode->label()} frame carries {$length} bytes; a control frame may carry at most "
                . self::MAX_CONTROL_PAYLOAD . '. This is a bug in the caller, not in the peer.',
            );
        }

        $first = ($this->fin ? 0x80 : 0x00) | $this->opcode->value;

        // The minimal form, which is the same rule decode() enforces. Writing
        // a non-minimal length here would produce frames this class would
        // refuse to read back, which is the kind of asymmetry a round-trip test
        // exists to catch.
        $header = match (true) {
            $length <= 125   => \chr($first) . \chr($length),
            $length <= 0xFFFF => \chr($first) . \chr(126) . pack('n', $length),
            default          => \chr($first) . \chr(127) . pack('J', $length),
        };

        return $header . $this->payload;
    }

    /**
     * Decode one frame from the front of $bytes.
     *
     * Returns null when $bytes does not yet hold a WHOLE frame — which is the
     * ordinary case on a stream, not an error, and is why this cannot simply
     * return a Frame. The caller keeps buffering and asks again; see
     * {@see FrameReader}.
     *
     * @param  bool $expectMasked true when reading from a client, which is the
     *                            only configuration this server uses. Passing
     *                            false is for decoding the frames this class
     *                            itself produced, in a test.
     * @return array{0: self, 1: int}|null the frame, and the bytes it consumed
     */
    public static function decode(string $bytes, bool $expectMasked = true, int $maxPayload = 0): ?array
    {
        $available = \strlen($bytes);

        if ($available < 2) {
            return null;
        }

        $first  = \ord($bytes[0]);
        $second = \ord($bytes[1]);

        $fin    = ($first & 0x80) !== 0;
        $rsv    = $first & 0x70;
        $opcode = Opcode::tryFrom($first & 0x0F);

        // RSV1-3 are for negotiated extensions. This server negotiates none, so
        // a set bit means the peer is speaking an extension we never agreed to
        // — and the payload may then be compressed, in which case every length
        // and every UTF-8 check below is being applied to the wrong bytes.
        if ($rsv !== 0) {
            throw ProtocolException::framing(
                'A frame sets a reserved bit (RSV1-3), but no extension was negotiated.',
            );
        }

        if ($opcode === null) {
            throw ProtocolException::framing(
                'A frame uses reserved opcode 0x' . dechex($first & 0x0F) . '.',
            );
        }

        $masked      = ($second & 0x80) !== 0;
        $shortLength = $second & 0x7F;

        if ($opcode->isControl()) {
            // Both rules, and each has its own reason. See Opcode.
            if (!$fin) {
                throw ProtocolException::framing(
                    "A {$opcode->label()} frame is fragmented; a control frame never may be.",
                );
            }

            if ($shortLength > self::MAX_CONTROL_PAYLOAD) {
                throw ProtocolException::framing(
                    "A {$opcode->label()} frame declares more than " . self::MAX_CONTROL_PAYLOAD . ' bytes.',
                );
            }
        }

        $offset = 2;

        if ($shortLength <= 125) {
            $length = $shortLength;
        } elseif ($shortLength === 126) {
            if ($available < $offset + 2) {
                return null;
            }

            /** @var array{1: int} $unpacked */
            $unpacked = unpack('n', $bytes, $offset);
            $length   = $unpacked[1];
            $offset  += 2;

            // The minimal-form rule. See the class docblock.
            if ($length <= 125) {
                throw ProtocolException::framing(
                    "A frame encodes a length of {$length} in 16 bits; the 7-bit form was required.",
                );
            }
        } else {
            if ($available < $offset + 8) {
                return null;
            }

            /** @var array{1: int} $unpacked */
            $unpacked = unpack('J', $bytes, $offset);
            $length   = $unpacked[1];
            $offset  += 8;

            // Read as a SIGNED 64-bit integer, so the specification's "most
            // significant bit MUST be 0" shows up here as a negative number.
            // Without this check a negative length makes every bounds test
            // below pass, which is the shape of an out-of-bounds read.
            if ($length < 0) {
                throw ProtocolException::framing('A frame declares a length with its high bit set.');
            }

            if ($length <= 0xFFFF) {
                throw ProtocolException::framing(
                    "A frame encodes a length of {$length} in 64 bits; a shorter form was required.",
                );
            }
        }

        // Checked BEFORE waiting for the body, which is the point of checking
        // it here at all: a peer that declares four gigabytes gets one small
        // close frame, rather than a server that politely buffers until it is
        // killed. A limit applied after the read is not a limit.
        if ($maxPayload > 0 && $length > $maxPayload) {
            throw ProtocolException::tooLarge(
                "A frame declares {$length} bytes, over this server's limit of {$maxPayload}.",
            );
        }

        if ($masked !== $expectMasked) {
            throw ProtocolException::framing(
                $expectMasked
                    ? 'A frame from a client is not masked. RFC 6455 requires it, and an unmasked client '
                        . 'frame is how a cache-poisoning proxy attack is attempted.'
                    : 'A frame from a server is masked, which RFC 6455 forbids.',
            );
        }

        if ($masked) {
            if ($available < $offset + self::MASK_BYTES) {
                return null;
            }

            $mask    = substr($bytes, $offset, self::MASK_BYTES);
            $offset += self::MASK_BYTES;
        } else {
            $mask = '';
        }

        if ($available < $offset + $length) {
            return null;
        }

        $payload = substr($bytes, $offset, $length);

        if ($mask !== '') {
            $payload = self::unmask($payload, $mask);
        }

        return [new self($opcode, $payload, $fin, $masked), $offset + $length];
    }

    // ── Payload rules that belong to specific frame types ────────────────────

    /**
     * The close code this frame states, or null when it states none.
     *
     * A close frame may legitimately be empty — that is what 1005 "no status"
     * means locally — but a non-empty one must be at least two bytes, because
     * a single byte is half a status code and there is no way to guess the
     * other half.
     */
    public function closeCode(): ?int
    {
        if ($this->opcode !== Opcode::Close) {
            return null;
        }

        $length = \strlen($this->payload);

        if ($length === 0) {
            return null;
        }

        if ($length === 1) {
            throw ProtocolException::framing('A close frame carries one byte; a status code needs two.');
        }

        /** @var array{1: int} $unpacked */
        $unpacked = unpack('n', $this->payload);
        $code     = $unpacked[1];

        if (!CloseCode::isValidOnTheWire($code)) {
            throw ProtocolException::framing("A close frame states status {$code}, which is not valid on the wire.");
        }

        // The reason, like any text the protocol carries, must be UTF-8 — and
        // it is checked here rather than ignored because a peer that sends
        // broken UTF-8 in a close reason will send it elsewhere too, and this
        // is the cheapest place to notice.
        $reason = substr($this->payload, 2);

        if ($reason !== '' && !mb_check_encoding($reason, 'UTF-8')) {
            throw ProtocolException::payload('A close frame\'s reason is not valid UTF-8.');
        }

        return $code;
    }

    /** A close frame's reason text, or ''. */
    public function closeReason(): string
    {
        return $this->opcode === Opcode::Close ? substr($this->payload, 2) : '';
    }

    /**
     * Assert that a text payload is UTF-8.
     *
     * Separate from decoding because a TEXT frame may be fragmented, and a
     * multi-byte character may be split across two fragments — so the check is
     * only meaningful once the message is whole. Running it per fragment would
     * reject a perfectly valid message that happened to be split mid-character,
     * which is a bug that appears only on messages larger than the peer's
     * buffer.
     */
    public static function assertUtf8(string $message): void
    {
        if (!mb_check_encoding($message, 'UTF-8')) {
            throw ProtocolException::payload('A text message is not valid UTF-8.');
        }
    }

    /**
     * XOR the payload with the four-byte mask.
     *
     * Done in 4-byte-aligned blocks with a single `^` on strings rather than a
     * loop over bytes. PHP's string XOR operates on the whole buffer in C, so a
     * megabyte payload costs one pass instead of a million interpreted
     * iterations — and this runs on every frame a client sends, which makes it
     * the hottest code in the server.
     */
    private static function unmask(string $payload, string $mask): string
    {
        $length = \strlen($payload);

        if ($length === 0) {
            return '';
        }

        // `^` on two strings stops at the SHORTER operand, so the key is grown
        // to at least the payload length and then cut back to it exactly.
        $key = str_repeat($mask, intdiv($length, self::MASK_BYTES) + 1);

        return $payload ^ substr($key, 0, $length);
    }
}
