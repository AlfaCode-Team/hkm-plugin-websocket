<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

/**
 * The RFC 6455 frame opcodes.
 *
 * Four bits, of which six values are defined and the rest are reserved. The
 * reserved ones are absent from this enum on purpose: {@see self::tryFrom()}
 * returning null is how {@see Frame::decode()} learns to fail, and a `Reserved`
 * member would have to be handled at every call site that switches on a kind.
 *
 * THE CONTROL/DATA SPLIT IS A SECURITY BOUNDARY, NOT A CATEGORY
 * ------------------------------------------------------------
 * A control frame (close, ping, pong) may carry at most 125 bytes and may never
 * be fragmented. Both limits exist so a control frame can always be delivered
 * between the fragments of a large message — a ping that could itself be
 * fragmented, or be a megabyte long, could not serve as a keepalive at all.
 *
 * The limits also bound an attack. Without them a peer can open a connection
 * and send a 2 GB ping, and a server that buffers it to reply with a matching
 * pong has been told to allocate 2 GB by an unauthenticated client.
 */
enum Opcode: int
{
    /** A continuation of the previous data frame. Carries no type of its own. */
    case Continuation = 0x0;

    case Text   = 0x1;
    case Binary = 0x2;

    case Close = 0x8;
    case Ping  = 0x9;
    case Pong  = 0xA;

    /** Close, ping and pong: at most 125 bytes, never fragmented. */
    public function isControl(): bool
    {
        return $this->value >= 0x8;
    }

    /** Text, binary and continuation: the frames that carry a message. */
    public function isData(): bool
    {
        return !$this->isControl();
    }

    public function label(): string
    {
        return strtolower($this->name);
    }
}
