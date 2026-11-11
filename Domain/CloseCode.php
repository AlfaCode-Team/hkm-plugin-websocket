<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

/**
 * The close status codes a server may send, and the rules for the ones it may
 * receive.
 *
 * WHY THE VALIDITY RULE IS A METHOD AND NOT A LIST
 * ------------------------------------------------
 * The registry is open: 3000–3999 is for libraries and frameworks, 4000–4999 is
 * for applications, and both are reachable by a peer that is behaving perfectly.
 * So a received code cannot be checked against an allowlist — it has to be
 * checked against the RANGES, which is what {@see self::isValidOnTheWire()}
 * does.
 *
 * The codes that must be REFUSED are the interesting half, and they are refused
 * because they do not mean anything on the wire:
 *
 *   1005 NoStatus      "no code was present" — sending it as a code is a
 *                      contradiction, and a peer that does is either confused
 *                      or probing;
 *   1006 Abnormal      "the connection dropped without a close frame" — it is
 *                      produced LOCALLY by an endpoint that saw a TCP close, so
 *                      receiving it in a close frame is impossible by
 *                      definition;
 *   1015 TlsFailure    likewise local: the handshake never completed, so there
 *                      was no connection to send a frame over.
 *
 * Letting those through is how a close code ends up logged as the peer's stated
 * reason when the peer never stated one — which turns "the network dropped"
 * into "the client asked to leave" in an operator's dashboard.
 */
enum CloseCode: int
{
    case Normal        = 1000;
    case GoingAway     = 1001;
    case ProtocolError = 1002;
    case Unsupported   = 1003;

    /** Local-only. Never on the wire. See the class docblock. */
    case NoStatus = 1005;

    /** Local-only. Never on the wire. */
    case Abnormal = 1006;

    case BadPayload       = 1007;
    case PolicyViolation  = 1008;
    case TooLarge         = 1009;
    case MissingExtension = 1010;
    case ServerError      = 1011;
    case TryAgainLater    = 1013;

    /** Local-only. Never on the wire. */
    case TlsFailure = 1015;

    /**
     * Whether $code may legitimately appear in a received close frame.
     *
     * Takes an int rather than a self, because the whole point is that a valid
     * code need not be a member of this enum: an application's own 4000-series
     * code is valid and will never be one.
     */
    public static function isValidOnTheWire(int $code): bool
    {
        // Local-only codes, refused first: each IS a member of this enum, so a
        // range check alone would let them through.
        if ($code === 1005 || $code === 1006 || $code === 1015) {
            return false;
        }

        // Defined protocol codes. 1004, 1012 and 1014 are unassigned in the
        // registry, and 1016–2999 is reserved for future protocol use — a peer
        // sending one is using a code neither end agrees on the meaning of.
        if ($code >= 1000 && $code <= 1015) {
            return $code !== 1004 && $code !== 1012 && $code !== 1014;
        }

        // 3000–3999 registered to libraries, 4000–4999 private to applications.
        return $code >= 3000 && $code <= 4999;
    }

    public function label(): string
    {
        return $this->name;
    }
}
