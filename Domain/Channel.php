<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

/**
 * A channel name a client may subscribe to.
 *
 * MATCHING IS EXACT. THERE ARE NO WILDCARDS, AND THAT IS A SECURITY DECISION
 * -------------------------------------------------------------------------
 * A hierarchy is the obvious feature to add here — let a client subscribe to
 * `documents.*` and receive everything under it. It is also the shortest path
 * to an authorisation bypass, because it inverts where the decision is made.
 *
 * With exact names, every channel a connection holds was authorised
 * individually: the authoriser was asked about `documents.42` and said yes
 * about `documents.42`. With a pattern, the authoriser is asked about
 * `documents.*` — a thing that does not exist and has no owner — and must then
 * somehow decide for every document that might ever match it, including the
 * ones created after the subscription was granted. Almost every implementation
 * answers that question once, at subscribe time, and then delivers to the
 * pattern forever.
 *
 * So a client that wants ten documents subscribes to ten channels and is
 * checked ten times. {@see \Plugins\WebSocket\Application\Services\ConnectionRegistry}
 * caps how many, which is the limit that makes this affordable.
 *
 * A SERVER may still publish to several channels at once — that is a fan-out
 * decision made by trusted code, not a subscription granted to a client.
 *
 * THE CHARSET IS NARROW ON PURPOSE. A channel name is used as an array key in
 * the registry, appears in log lines, and on some buses becomes part of a topic
 * — so control characters, whitespace and the separators of every downstream
 * format are refused rather than escaped at each use. A name is also LENGTH
 * CAPPED because the registry is keyed by it: without a cap, a client can spend
 * the server's memory on names alone, which costs nothing to send.
 */
final readonly class Channel
{
    /**
     * 128 bytes. Long enough for a prefix and a UUID — `collections.` plus a
     * 36-character id is 48 — and short enough that the registry's memory is
     * bounded by its subscription cap rather than by name length.
     */
    public const MAX_LENGTH = 128;

    private function __construct(public string $name) {}

    /**
     * Validate a name, or null when it is not one.
     *
     * Null rather than an exception: this runs on a string an unauthenticated
     * client chose, so a bad value is the ordinary case and not an error
     * condition. The caller answers with a refusal frame.
     */
    public static function parse(string $raw): ?self
    {
        // WHITESPACE ONLY, named explicitly. PHP's `trim()` defaults to
        // " \t\n\r\0\x0B" — it strips the NUL BYTE and the vertical tab as
        // well as whitespace, which is not what a reader of `trim($raw)`
        // expects and is not what this class documents. With the default,
        // "documents.42\0" arrived, lost its NUL, and was accepted as the
        // perfectly valid channel "documents.42" — so a name carrying a
        // control byte was quietly normalised into a good one instead of being
        // refused, and the charset check below never saw it.
        //
        // Nothing was reachable through that: the trimmed name is what gets
        // authorised AND what gets stored, so the two cannot diverge. But a
        // NUL in a channel name means a broken client or somebody looking for
        // a parser difference, and either is worth a refusal rather than a
        // silent repair.
        $name = trim($raw, " \t\n\r");

        if ($name === '' || \strlen($name) > self::MAX_LENGTH) {
            return null;
        }

        // Letters, digits, and the three separators a hierarchy is written
        // with. No `*`, `?` or `#` — not because this class would interpret
        // them, but because it would NOT: a client sending `documents.*` and
        // being granted a channel literally named `documents.*` would receive
        // nothing, see a successful subscription, and report the feature as
        // broken rather than as refused.
        if (preg_match('/^[A-Za-z0-9._:-]+$/', $name) !== 1) {
            return null;
        }

        // No empty segments. `documents..42` and a trailing dot are almost
        // always a client building a name from a missing variable, and both
        // would otherwise be accepted as distinct channels that nothing ever
        // publishes to — a subscription that silently receives nothing.
        if (str_contains($name, '..') || str_starts_with($name, '.') || str_ends_with($name, '.')) {
            return null;
        }

        return new self($name);
    }

    /**
     * The first segment, e.g. `documents` of `documents.42`.
     *
     * What an authoriser usually switches on: the KIND of thing is in the
     * prefix and the identity of one in the rest.
     */
    public function prefix(): string
    {
        $dot = strpos($this->name, '.');

        return $dot === false ? $this->name : substr($this->name, 0, $dot);
    }

    /** Everything after the first segment, or ''. */
    public function identifier(): string
    {
        $dot = strpos($this->name, '.');

        return $dot === false ? '' : substr($this->name, $dot + 1);
    }

    public function equals(self $other): bool
    {
        return $this->name === $other->name;
    }

    public function __toString(): string
    {
        return $this->name;
    }
}
