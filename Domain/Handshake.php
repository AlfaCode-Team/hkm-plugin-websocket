<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain;

use Plugins\WebSocket\Domain\Exceptions\ProtocolException;

/**
 * The HTTP Upgrade that turns a request into a WebSocket.
 *
 * CHECKING `Origin` IS THE MOST IMPORTANT THING THIS CLASS DOES
 * ------------------------------------------------------------
 * More important than the key, the version, or the framing — because it is the
 * one check with no fallback anywhere else in the stack, and the one that is
 * most often missing.
 *
 * **A WebSocket handshake is exempt from the same-origin policy.** A browser
 * will let any page open a socket to any host, it does NOT perform a CORS
 * preflight, and it DOES attach the target site's cookies. So this, served from
 * anywhere on the internet, runs in a logged-in victim's browser:
 *
 *     new WebSocket('wss://app.example.com/realtime')
 *
 * …and the connection arrives authenticated as that user. Every subscription it
 * makes and every message it receives goes to the attacker's page. That is
 * Cross-Site WebSocket Hijacking, and the server's `Origin` header is the only
 * place it can be stopped: the browser sets it, a page cannot forge it, and
 * nothing else in the request distinguishes the attacker's page from the real
 * one.
 *
 * Which is why {@see self::$allowedOrigins} has NO DEFAULT and an empty list
 * REFUSES EVERYTHING. A permissive default would mean every deployment that did
 * not think about this shipped the vulnerability, and it would never show up in
 * testing, because the legitimate client works perfectly either way.
 *
 * A NON-BROWSER CLIENT SENDS NO `Origin`, and that case is a configuration
 * decision rather than a judgement this class can make. A mobile app or a
 * server-to-server client has no origin to send; so does `curl`, and so does an
 * attacker's script running outside a browser — but an attacker outside a
 * browser has no victim's cookies to borrow, which is the entire point. So
 * {@see self::$requireOrigin} defaults to true (browser-only, the safe
 * assumption for a web application) and a deployment serving native clients
 * turns it off and authenticates them by token instead.
 *
 * WHAT IS DELIBERATELY NOT NEGOTIATED
 * -----------------------------------
 * No extensions, ever. `permessage-deflate` is the one a browser will offer, and
 * echoing it back without implementing it is catastrophic rather than merely
 * wrong: the client would then compress every payload, the RSV1 bit would be
 * set on every frame, and this server reads neither — so every message would be
 * rejected as a protocol violation, or worse, read as garbage. The response
 * therefore omits `Sec-WebSocket-Extensions` entirely, which is how a server
 * declines.
 */
final readonly class Handshake
{
    /**
     * The magic string from RFC 6455 §1.3.
     *
     * Its purpose is to make the response impossible to produce by accident: a
     * cache or a proxy replaying a 101 it did not understand cannot compute the
     * accept value, because it would have to know this constant and perform the
     * hash. It is not a secret — it is in the specification — and it is not
     * configurable.
     */
    public const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

    public const VERSION = 13;

    /** @param list<string> $allowedOrigins exact origins, e.g. https://app.example.com */
    public function __construct(
        private array $allowedOrigins = [],
        /** Whether a request with no `Origin` header is refused. See the class docblock. */
        private bool $requireOrigin = true,
        /** @var list<string> subprotocols this server will accept, best first */
        private array $subprotocols = [],
    ) {}

    /**
     * Validate an upgrade request and produce the response headers.
     *
     * @param  array<string, string|list<string>> $headers as received, any case
     * @return array<string, string>              headers for the 101 response
     * @throws ProtocolException when the request is not a valid upgrade, or the
     *         origin is not permitted
     */
    public function accept(string $method, array $headers): array
    {
        $get = static function (string $name) use ($headers): string {
            foreach ($headers as $key => $value) {
                if (strcasecmp($key, $name) === 0) {
                    return \is_array($value) ? (string) ($value[0] ?? '') : $value;
                }
            }

            return '';
        };

        if (strtoupper($method) !== 'GET') {
            throw ProtocolException::framing("A WebSocket upgrade must be a GET; this was a {$method}.");
        }

        // A TOKEN LIST, not a string comparison. Behind a proxy a browser sends
        // `Connection: keep-alive, Upgrade`, so `=== 'Upgrade'` refuses real
        // clients in exactly the deployment where a WebSocket is hardest to
        // debug. Both headers are case-insensitive in value as well as name.
        if (!self::listContains($get('Connection'), 'upgrade')) {
            throw ProtocolException::framing('The request has no `Connection: Upgrade`.');
        }

        if (!self::listContains($get('Upgrade'), 'websocket')) {
            throw ProtocolException::framing('The request has no `Upgrade: websocket`.');
        }

        $version = (int) $get('Sec-WebSocket-Version');

        if ($version !== self::VERSION) {
            // The reply to this one should carry `Sec-WebSocket-Version: 13` so
            // a client speaking an older draft learns what to offer. The caller
            // builds that response; this reports which version arrived.
            throw ProtocolException::framing(
                "The request offers WebSocket version {$version}; this server speaks only "
                . self::VERSION . '.',
            );
        }

        $key = trim($get('Sec-WebSocket-Key'));

        if (!self::isValidKey($key)) {
            throw ProtocolException::framing(
                'The `Sec-WebSocket-Key` is not 16 base64-encoded bytes.',
            );
        }

        $this->assertOriginAllowed($get('Origin'));

        $response = [
            'Upgrade'              => 'websocket',
            'Connection'           => 'Upgrade',
            'Sec-WebSocket-Accept' => self::accepted($key),
        ];

        $chosen = $this->chooseSubprotocol($get('Sec-WebSocket-Protocol'));

        if ($chosen !== '') {
            $response['Sec-WebSocket-Protocol'] = $chosen;
        }

        // No Sec-WebSocket-Extensions key at all. See the class docblock: an
        // echoed extension this server does not implement breaks every frame.
        return $response;
    }

    /**
     * `base64(sha1(key . GUID))`.
     *
     * `sha1(..., true)` for the RAW digest. Without the second argument PHP
     * returns 40 hex CHARACTERS, which base64-encodes to a 56-character value
     * that is the right shape and the wrong answer — so every browser refuses
     * the handshake and the server looks like it is not running. It is the
     * single most common mistake in a hand-written implementation.
     */
    public static function accepted(string $key): string
    {
        return base64_encode(sha1($key . self::GUID, true));
    }

    /**
     * Exactly 16 bytes, base64-encoded.
     *
     * The specification makes this the client's obligation and lets a server
     * fail the handshake when it is wrong. Checked here because the key's only
     * job is to be unguessable, and a client that sends a short or
     * non-canonical one is not a browser — so the handshake is the cheapest
     * place to find out what is really connecting.
     */
    public static function isValidKey(string $key): bool
    {
        if (preg_match('#^[A-Za-z0-9+/]{22}==$#', $key) !== 1) {
            return false;
        }

        $decoded = base64_decode($key, true);

        return $decoded !== false && \strlen($decoded) === 16;
    }

    /** A fresh client key, for a test or a client implementation. */
    public static function newKey(): string
    {
        return base64_encode(random_bytes(16));
    }

    /**
     * @throws ProtocolException when the origin is absent and required, or
     *         present and not allowed
     */
    private function assertOriginAllowed(string $origin): void
    {
        $origin = trim($origin);

        if ($origin === '') {
            if ($this->requireOrigin) {
                throw ProtocolException::policy(
                    'The request carries no `Origin` header. This server requires one, because the header '
                    . 'is the only defence against a page on another site opening an authenticated socket '
                    . 'with the visitor\'s cookies. Set WEBSOCKET_REQUIRE_ORIGIN=false only for '
                    . 'non-browser clients, which must then authenticate by token.',
                );
            }

            return;
        }

        foreach ($this->allowedOrigins as $permitted) {
            // Exact, case-insensitive on the whole origin. NOT a suffix match:
            // `str_ends_with($origin, 'example.com')` accepts
            // `https://evil-example.com` and `https://example.com.attacker.net`,
            // which are different sites that a suffix test cannot distinguish.
            // The scheme is part of it too, so an http origin never satisfies
            // an https allowlist.
            if (strcasecmp(rtrim($permitted, '/'), rtrim($origin, '/')) === 0) {
                return;
            }
        }

        throw ProtocolException::policy(
            "The origin [{$origin}] is not permitted to open a socket to this server.",
        );
    }

    /**
     * The one subprotocol to echo, or ''.
     *
     * At most ONE, and only one the client offered. Echoing a value the client
     * did not offer, or several, is a protocol violation that browsers respond
     * to by closing the connection immediately after a successful handshake —
     * which presents as "it connects and then disconnects" with nothing in any
     * log.
     */
    private function chooseSubprotocol(string $offered): string
    {
        if ($offered === '' || $this->subprotocols === []) {
            return '';
        }

        $wanted = array_map('trim', explode(',', $offered));

        // This server's preference order wins, not the client's. Both are
        // permitted by the specification; a server that follows its own order
        // can deprecate a protocol by moving it down the list rather than
        // waiting for every client to stop asking for it first.
        foreach ($this->subprotocols as $candidate) {
            foreach ($wanted as $request) {
                if (strcasecmp($candidate, $request) === 0) {
                    return $candidate;
                }
            }
        }

        return '';
    }

    /** Whether a comma-separated header value contains $token, case-insensitively. */
    private static function listContains(string $header, string $token): bool
    {
        foreach (explode(',', $header) as $part) {
            if (strcasecmp(trim($part), $token) === 0) {
                return true;
            }
        }

        return false;
    }
}
