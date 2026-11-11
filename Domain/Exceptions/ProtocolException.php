<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain\Exceptions;

use Plugins\WebSocket\Domain\CloseCode;

/**
 * A frame or handshake that broke the protocol.
 *
 * CARRIES THE CLOSE CODE, which is the only reason this is a class and not a
 * plain exception. RFC 6455 does not just say "fail" — it says which status to
 * close WITH, and the distinction is observable by the peer:
 *
 *   1002 the framing was wrong      — a bad length, a reserved bit, no mask
 *   1007 the payload was wrong      — invalid UTF-8 in a text or close frame
 *   1009 the message was too big    — over this server's configured limit
 *
 * A client library uses the code to decide whether to retry. Close everything
 * with 1002 and a client that sent one oversized message reconnects forever,
 * because "protocol error" tells it the connection was broken rather than that
 * its message was.
 *
 * The MESSAGE is for the log and is not sent. A close frame's reason is capped
 * at 123 bytes and is read by whoever wrote the client, so the server's internal
 * detail does not belong there — see {@see \Plugins\WebSocket\Domain\Frame::close()}.
 */
final class ProtocolException extends \RuntimeException
{
    private function __construct(
        string $message,
        public readonly CloseCode $closeCode,
    ) {
        parent::__construct($message);
    }

    /** The framing was malformed — the 1002 case. */
    public static function framing(string $reason): self
    {
        return new self($reason, CloseCode::ProtocolError);
    }

    /** The bytes were not what the frame's type requires — the 1007 case. */
    public static function payload(string $reason): self
    {
        return new self($reason, CloseCode::BadPayload);
    }

    /** Over a configured limit — the 1009 case. */
    public static function tooLarge(string $reason): self
    {
        return new self($reason, CloseCode::TooLarge);
    }

    /** Refused by policy: an origin, a channel, an authorisation — the 1008 case. */
    public static function policy(string $reason): self
    {
        return new self($reason, CloseCode::PolicyViolation);
    }
}
