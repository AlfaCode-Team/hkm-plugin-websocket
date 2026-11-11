<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

/**
 * What {@see FrameReader} hands back: either a whole application message or a
 * control frame that needs answering.
 *
 * ONE TYPE FOR BOTH, because the caller's loop has to handle them in ORDER. A
 * reader that returned messages from one method and control frames from another
 * would lose the interleaving — and the interleaving is the whole reason control
 * frames exist: a ping sent between two fragments must be answered before the
 * message completes, or the peer times the connection out while it is working
 * perfectly.
 */
final readonly class Message
{
    private function __construct(
        public Opcode $opcode,
        public string $payload,
        /** The frame itself, for a control message. Null for reassembled data. */
        public ?Frame $frame = null,
    ) {}

    /** A complete application message, possibly reassembled from fragments. */
    public static function data(Opcode $opcode, string $payload): self
    {
        return new self($opcode, $payload);
    }

    /** A close, ping or pong frame, passed straight through. */
    public static function control(Frame $frame): self
    {
        return new self($frame->opcode, $frame->payload, $frame);
    }

    public function isControl(): bool
    {
        return $this->opcode->isControl();
    }

    public function isText(): bool
    {
        return $this->opcode === Opcode::Text;
    }

    /**
     * The payload decoded as a JSON object, or null when it is not one.
     *
     * Null rather than an exception, and a DEPTH LIMIT, because this is the
     * first thing done with bytes an unauthenticated client chose. A deeply
     * nested document is the cheap way to make a JSON parser recurse, and the
     * limit costs nothing on the documents a real client sends — a subscribe
     * message is two levels deep.
     *
     * @return array<string, mixed>|null
     */
    public function json(int $maxDepth = 16): ?array
    {
        if (!$this->isText() || $this->payload === '') {
            return null;
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode(
                $this->payload,
                true,
                // Clamped. json_decode() requires a depth of at least 1 and
                // throws a ValueError below it, so a caller passing 0 — or a
                // configured value that arrived as an empty string and cast to
                // 0 — would turn a malformed client message into a fatal.
                max(1, $maxDepth),
                JSON_THROW_ON_ERROR,
            );
        } catch (\JsonException) {
            return null;
        }

        if (!\is_array($decoded)) {
            return null;
        }

        // A JSON ARRAY decodes to a PHP list, which is not the object shape
        // every caller here expects: on a list, `$payload['type']` is silently
        // null, indistinguishable from an object that omitted the field — so a
        // malformed message would be handled as a valid one with a missing key.
        //
        // The check runs BEFORE the array is narrowed to array<string, mixed>,
        // which is the order that matters. Annotating first and checking after
        // is what the previous version did, and PHPStan was right to call the
        // check dead: once the value is DECLARED string-keyed, `array_is_list`
        // provably cannot be true — to the analyser. At runtime it still was,
        // because json_decode genuinely returns a list for `[...]`. So the
        // annotation was making a true claim unverifiable rather than making
        // the code safe.
        if (array_is_list($decoded) && $decoded !== []) {
            return null;
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
