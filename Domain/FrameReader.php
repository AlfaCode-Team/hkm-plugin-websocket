<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

use Plugins\WebSocket\Domain\Exceptions\ProtocolException;

/**
 * Turns a byte STREAM into whole messages, reassembling fragments.
 *
 * WHY THIS IS A SEPARATE CLASS FROM {@see Frame}
 * ----------------------------------------------
 * A frame is not a message. TCP delivers bytes, not frames: one `recv()` may
 * return half a frame, three frames, or two and a half. And a single message
 * may arrive as a chain of fragments — a text frame with FIN clear, then any
 * number of continuation frames, then one with FIN set.
 *
 * So there are two jobs, and conflating them is how servers end up with the
 * bugs below. {@see Frame::decode()} answers "is there a whole frame at the
 * front of this buffer"; this class answers "is there a whole message yet".
 *
 * THE FOUR FRAGMENTATION RULES, AND WHAT EACH ONE PREVENTS
 * --------------------------------------------------------
 * | Rule | Violated |
 * |---|---|
 * | a continuation needs an open message | a peer sends CONT first and the server appends to a buffer that was never started — in a naive implementation, to the PREVIOUS message's buffer |
 * | a new TEXT/BINARY may not interrupt one | two interleaved messages are spliced into one, so a payload can be smuggled into the middle of a legitimate message |
 * | a control frame may interleave freely | a ping between fragments is REQUIRED to work; a server that routes it into the reassembly buffer corrupts the message with its own keepalive |
 * | the total is bounded, not just each frame | a peer sends a million 1-byte fragments and never sets FIN, and a per-frame limit never fires while memory fills |
 *
 * That last one is the one a per-frame size check feels like it has already
 * handled, and it has not: `maxPayload` bounds one frame, `maxMessage` bounds
 * their sum. Both are needed and they are not the same number.
 *
 * UTF-8 IS CHECKED ON THE WHOLE MESSAGE, NEVER PER FRAGMENT. A multi-byte
 * character may legally straddle a fragment boundary, so a per-fragment check
 * rejects valid traffic — and only for messages large enough to be split, which
 * is to say only in production.
 */
final class FrameReader
{
    private string $buffer = '';

    /** The message being reassembled: its opcode, or null when none is open. */
    private ?Opcode $fragmentOpcode = null;

    private string $fragments = '';

    public function __construct(
        /**
         * Ceiling on ONE frame's declared payload, enforced before the body is
         * read. See {@see Frame::decode()}.
         */
        private readonly int $maxPayload = 2_097_152,
        /**
         * Ceiling on a reassembled message. Separate from maxPayload, for the
         * reason in the class docblock.
         */
        private readonly int $maxMessage = 8_388_608,
    ) {}

    /** Hand the reader whatever just arrived from the socket. */
    public function feed(string $bytes): void
    {
        $this->buffer .= $bytes;
    }

    /**
     * Every complete item the buffer now yields, in order.
     *
     * Returns {@see Message} objects — a whole application message, or a
     * control frame that needs answering. Control frames are passed through
     * individually and immediately rather than queued behind a half-finished
     * message, because a ping that waits for the message around it to finish is
     * a keepalive that times out exactly when the connection is busy.
     *
     * @return list<Message>
     */
    public function drain(): array
    {
        $messages = [];

        while (true) {
            $decoded = Frame::decode($this->buffer, expectMasked: true, maxPayload: $this->maxPayload);

            if ($decoded === null) {
                // A partial frame. Keep it and wait for more bytes.
                return $messages;
            }

            [$frame, $consumed] = $decoded;

            $this->buffer = substr($this->buffer, $consumed);

            $message = $this->accept($frame);

            if ($message !== null) {
                $messages[] = $message;
            }
        }
    }

    /** Bytes held but not yet forming a frame — for a status command. */
    public function buffered(): int
    {
        return \strlen($this->buffer) + \strlen($this->fragments);
    }

    /**
     * Fold one frame into the reader's state.
     *
     * @return Message|null a message when one completed, else null
     */
    private function accept(Frame $frame): ?Message
    {
        // Control frames bypass reassembly entirely. They are complete by
        // definition — a control frame can never be fragmented — so there is
        // nothing to accumulate and nothing to interrupt.
        if ($frame->opcode->isControl()) {
            return Message::control($frame);
        }

        if ($frame->opcode === Opcode::Continuation) {
            if ($this->fragmentOpcode === null) {
                throw ProtocolException::framing(
                    'A continuation frame arrived with no message open.',
                );
            }

            return $this->append($frame, $this->fragmentOpcode);
        }

        // A data frame while a message is already open. Refused rather than
        // treated as a fresh start: either reading is wrong, and splicing two
        // messages together is the one that cannot be detected downstream.
        if ($this->fragmentOpcode !== null) {
            throw ProtocolException::framing(
                "A {$frame->opcode->label()} frame arrived while a fragmented message was still open.",
            );
        }

        // The common case: a whole message in one unfragmented frame. Handled
        // without touching the fragment buffer at all, so the ordinary path
        // costs no copy.
        if ($frame->fin) {
            if ($frame->opcode === Opcode::Text) {
                Frame::assertUtf8($frame->payload);
            }

            return Message::data($frame->opcode, $frame->payload);
        }

        $this->fragmentOpcode = $frame->opcode;
        $this->fragments      = '';

        return $this->append($frame, $frame->opcode);
    }

    private function append(Frame $frame, Opcode $opcode): ?Message
    {
        $total = \strlen($this->fragments) + \strlen($frame->payload);

        if ($total > $this->maxMessage) {
            // Reset before throwing. The caller closes the connection on a
            // protocol exception, but this object may be reused by a test or a
            // caller that chooses to continue, and leaving half a rejected
            // message in the buffer would prepend it to the next one.
            $this->reset();

            throw ProtocolException::tooLarge(
                "A fragmented message reached {$total} bytes, over this server's limit of {$this->maxMessage}.",
            );
        }

        $this->fragments .= $frame->payload;

        if (!$frame->fin) {
            return null;
        }

        $payload = $this->fragments;

        $this->reset();

        // Now that the message is whole. See the class docblock on why this
        // cannot happen per fragment.
        if ($opcode === Opcode::Text) {
            Frame::assertUtf8($payload);
        }

        return Message::data($opcode, $payload);
    }

    private function reset(): void
    {
        $this->fragmentOpcode = null;
        $this->fragments      = '';
    }
}
