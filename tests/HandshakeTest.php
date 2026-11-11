<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\WebSocket;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\WebSocket\Domain\Exceptions\ProtocolException;
use Plugins\WebSocket\Domain\Handshake;

/**
 * The HTTP Upgrade.
 *
 * THE ACCEPT VALUE IS CHECKED AGAINST THE RFC'S OWN VECTOR
 * --------------------------------------------------------
 * RFC 6455 §1.3 prints one worked example, and
 * {@see self::test_the_rfc_6455_worked_example_is_reproduced()} reproduces it.
 * That is worth more than any number of round-trip tests, because it comes from
 * outside this codebase: the specification chose both the key and the answer,
 * so a hash applied in the wrong order, a hex digest instead of a raw one, or a
 * mistyped GUID all fail it. A self-consistent implementation of the wrong
 * algorithm passes everything else in this file.
 *
 * THE ORIGIN TESTS ARE THE SECURITY TESTS
 * ---------------------------------------
 * A WebSocket handshake is not subject to the same-origin policy and the
 * browser sends cookies with it, so `Origin` is the only thing standing between
 * a logged-in user and any page on the internet opening an authenticated socket
 * on their behalf. The refusals below are therefore not input validation; they
 * are the whole defence against Cross-Site WebSocket Hijacking.
 */
#[CoversClass(Handshake::class)]
final class HandshakeTest extends TestCase
{
    private const ORIGIN = 'https://app.example.com';

    /**
     * The worked example from RFC 6455 §1.3, verbatim.
     *
     * The key decodes to the ASCII text "the sample nonce", which is 16 bytes,
     * so it is a conforming key as well as the published one.
     */
    public function test_the_rfc_6455_worked_example_is_reproduced(): void
    {
        self::assertSame(
            's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
            Handshake::accepted('dGhlIHNhbXBsZSBub25jZQ=='),
            'the Sec-WebSocket-Accept algorithm does not match the specification',
        );
    }

    /**
     * The mistake the vector above exists to catch.
     *
     * `sha1($x)` without the second argument returns 40 HEX CHARACTERS, which
     * base64-encode to a 56-character string — the right shape, the wrong
     * answer, and every browser silently refuses the handshake. Asserting the
     * two differ documents that the raw digest is load-bearing.
     */
    public function test_a_hex_digest_would_produce_a_different_answer(): void
    {
        $key = 'dGhlIHNhbXBsZSBub25jZQ==';

        self::assertNotSame(
            base64_encode(sha1($key . Handshake::GUID)),
            Handshake::accepted($key),
            'sha1() must be called with raw_output = true',
        );
    }

    public function test_a_valid_upgrade_is_accepted(): void
    {
        $key      = Handshake::newKey();
        $response = $this->handshake()->accept('GET', [
            'Host'                  => 'app.example.com',
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => $key,
            'Sec-WebSocket-Version' => '13',
            'Origin'                => self::ORIGIN,
        ]);

        self::assertSame('websocket', $response['Upgrade']);
        self::assertSame('Upgrade', $response['Connection']);
        self::assertSame(Handshake::accepted($key), $response['Sec-WebSocket-Accept']);
    }

    /** Header names are case-insensitive, and real clients vary. */
    public function test_header_names_are_matched_case_insensitively(): void
    {
        $key      = Handshake::newKey();
        $response = $this->handshake()->accept('GET', [
            'UPGRADE'               => 'websocket',
            'connection'            => 'Upgrade',
            'sec-websocket-key'     => $key,
            'Sec-Websocket-Version' => '13',
            'ORIGIN'                => self::ORIGIN,
        ]);

        self::assertSame(Handshake::accepted($key), $response['Sec-WebSocket-Accept']);
    }

    /**
     * `Connection: keep-alive, Upgrade` is accepted.
     *
     * Which is what a browser sends through a proxy. A server comparing the
     * whole header with 'Upgrade' refuses real clients in exactly the
     * deployment where a WebSocket is hardest to debug — behind a load
     * balancer, where there is nothing to read on either side.
     */
    #[DataProvider('connectionHeaders')]
    public function test_the_connection_header_is_parsed_as_a_token_list(string $header, bool $accepted): void
    {
        $call = fn (): array => $this->handshake()->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => $header,
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
            'Origin'                => self::ORIGIN,
        ]);

        if (!$accepted) {
            $this->assertRefused('Connection: Upgrade', $call);

            return;
        }

        self::assertArrayHasKey('Sec-WebSocket-Accept', $call());
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function connectionHeaders(): iterable
    {
        yield 'plain'                 => ['Upgrade', true];
        yield 'lower case'            => ['upgrade', true];
        yield 'behind a proxy'        => ['keep-alive, Upgrade', true];
        yield 'reordered'             => ['Upgrade, keep-alive', true];
        yield 'spaced'                => ['keep-alive,  upgrade ', true];
        yield 'absent'                => ['', false];
        yield 'keep-alive only'       => ['keep-alive', false];
        yield 'a word containing it'  => ['Upgrades', false];
    }

    // ── Origin: the Cross-Site WebSocket Hijacking defence ───────────────────

    /**
     * An origin that is not on the list is refused with 1008.
     *
     * This is the attack: the page is served from evil.example, the browser
     * attaches app.example.com's cookies anyway because WebSocket is exempt
     * from the same-origin policy, and the handshake arrives looking exactly
     * like the real client's except for this header.
     */
    public function test_a_foreign_origin_is_refused(): void
    {
        $this->assertRefused('not permitted', fn () => $this->handshake()->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
            'Origin'                => 'https://evil.example',
        ]));
    }

    /**
     * Matching is exact, not a suffix test.
     *
     * `str_ends_with($origin, 'example.com')` is the natural shortcut and it
     * accepts every one of these, each of which is a different site under
     * somebody else's control.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function lookalikeOrigins(): iterable
    {
        yield 'a prefixed domain'      => ['https://evil-app.example.com'];
        yield 'a suffixed domain'      => ['https://app.example.com.attacker.net'];
        yield 'a subdomain'            => ['https://sub.app.example.com'];
        yield 'the parent domain'      => ['https://example.com'];
        yield 'plain http'             => ['http://app.example.com'];
        yield 'a different port'       => ['https://app.example.com:8443'];
        yield 'a path appended'        => ['https://app.example.com/evil'];
        yield 'a userinfo prefix'      => ['https://app.example.com@evil.example'];
    }

    #[DataProvider('lookalikeOrigins')]
    public function test_a_lookalike_origin_is_refused(string $origin): void
    {
        $this->assertRefused('not permitted', fn () => $this->handshake()->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
            'Origin'                => $origin,
        ]));
    }

    /**
     * An EMPTY allowlist refuses everything, including the right answer.
     *
     * The default, and deliberately useless: a permissive default would mean
     * every deployment that did not think about this shipped the vulnerability,
     * and it would never show up in testing because the legitimate client works
     * either way.
     */
    public function test_an_empty_allowlist_refuses_every_origin(): void
    {
        $handshake = new Handshake(allowedOrigins: []);

        $this->assertRefused('not permitted', fn () => $handshake->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
            'Origin'                => self::ORIGIN,
        ]));
    }

    /** A missing Origin is refused by default: the browser-client assumption. */
    public function test_a_missing_origin_is_refused_by_default(): void
    {
        $this->assertRefused('no `Origin` header', fn () => $this->handshake()->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
        ]));
    }

    /**
     * …and allowed when the deployment says it serves non-browser clients.
     *
     * A native app has no origin to send. Neither has an attacker's script
     * running outside a browser — but one outside a browser has no victim's
     * cookies to borrow, which is the entire reason the header matters.
     */
    public function test_a_missing_origin_is_allowed_when_not_required(): void
    {
        $handshake = new Handshake(allowedOrigins: [self::ORIGIN], requireOrigin: false);

        $response = $handshake->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
        ]);

        self::assertArrayHasKey('Sec-WebSocket-Accept', $response);
    }

    /** A PRESENT origin is still checked, even when one is not required. */
    public function test_a_present_origin_is_still_checked_when_not_required(): void
    {
        $handshake = new Handshake(allowedOrigins: [self::ORIGIN], requireOrigin: false);

        $this->assertRefused('not permitted', fn () => $handshake->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
            'Origin'                => 'https://evil.example',
        ]));
    }

    // ── Version, method and key ─────────────────────────────────────────────

    public function test_a_non_get_request_is_refused(): void
    {
        $this->assertRefused('must be a GET', fn () => $this->handshake()->accept('POST', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => '13',
            'Origin'                => self::ORIGIN,
        ]));
    }

    #[DataProvider('badVersions')]
    public function test_a_version_other_than_13_is_refused(string $version): void
    {
        $this->assertRefused('version', fn () => $this->handshake()->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => Handshake::newKey(),
            'Sec-WebSocket-Version' => $version,
            'Origin'                => self::ORIGIN,
        ]));
    }

    /** @return iterable<string, array{0: string}> */
    public static function badVersions(): iterable
    {
        yield 'an old draft' => ['8'];
        yield 'a future one' => ['14'];
        yield 'absent'       => [''];
        yield 'not a number' => ['thirteen'];
    }

    #[DataProvider('badKeys')]
    public function test_a_malformed_key_is_refused(string $key): void
    {
        self::assertFalse(Handshake::isValidKey($key));

        $this->assertRefused('base64-encoded bytes', fn () => $this->handshake()->accept('GET', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => $key,
            'Sec-WebSocket-Version' => '13',
            'Origin'                => self::ORIGIN,
        ]));
    }

    /** @return iterable<string, array{0: string}> */
    public static function badKeys(): iterable
    {
        yield 'empty'                  => [''];
        yield 'not base64'             => ['!!!!!!!!!!!!!!!!!!!!!!=='];
        yield 'too short when decoded' => [base64_encode('short')];
        yield 'too long when decoded'  => [base64_encode(str_repeat('x', 32))];
        yield 'unpadded'               => ['dGhlIHNhbXBsZSBub25jZQ'];
        yield 'base64url alphabet'     => ['dGhlIHNhbXBsZSBub25j-Q=='];
    }

    /** A freshly generated key must satisfy the validator. */
    public function test_a_generated_key_is_valid(): void
    {
        for ($i = 0; $i < 50; ++$i) {
            $key = Handshake::newKey();

            self::assertTrue(Handshake::isValidKey($key), "generated key [{$key}] was rejected");
        }
    }

    // ── Subprotocols and extensions ─────────────────────────────────────────

    public function test_a_subprotocol_is_echoed_when_offered_and_supported(): void
    {
        $handshake = new Handshake(allowedOrigins: [self::ORIGIN], subprotocols: ['hkm.realtime.v1']);

        $response = $handshake->accept('GET', [
            'Upgrade'                => 'websocket',
            'Connection'             => 'Upgrade',
            'Sec-WebSocket-Key'      => Handshake::newKey(),
            'Sec-WebSocket-Version'  => '13',
            'Origin'                 => self::ORIGIN,
            'Sec-WebSocket-Protocol' => 'something.else, hkm.realtime.v1',
        ]);

        self::assertSame('hkm.realtime.v1', $response['Sec-WebSocket-Protocol']);
    }

    /**
     * A subprotocol the client did NOT offer is never echoed.
     *
     * Echoing one is a protocol violation that browsers answer by closing the
     * connection right after a successful handshake — which presents as "it
     * connects and then disconnects" with nothing in any log.
     */
    public function test_a_subprotocol_the_client_did_not_offer_is_not_echoed(): void
    {
        $handshake = new Handshake(allowedOrigins: [self::ORIGIN], subprotocols: ['hkm.realtime.v1']);

        $response = $handshake->accept('GET', [
            'Upgrade'                => 'websocket',
            'Connection'             => 'Upgrade',
            'Sec-WebSocket-Key'      => Handshake::newKey(),
            'Sec-WebSocket-Version'  => '13',
            'Origin'                 => self::ORIGIN,
            'Sec-WebSocket-Protocol' => 'graphql-ws',
        ]);

        self::assertArrayNotHasKey('Sec-WebSocket-Protocol', $response);
    }

    /**
     * An offered extension is NEVER echoed.
     *
     * The failure this prevents is total rather than cosmetic. A browser offers
     * `permessage-deflate`; echo it and the client compresses every payload and
     * sets RSV1 on every frame — and this server implements neither, so every
     * message afterwards is either rejected as a reserved-bit violation or read
     * as garbage. Omitting the header is how a server declines.
     */
    public function test_an_offered_extension_is_never_echoed(): void
    {
        $response = $this->handshake()->accept('GET', [
            'Upgrade'                  => 'websocket',
            'Connection'               => 'Upgrade',
            'Sec-WebSocket-Key'        => Handshake::newKey(),
            'Sec-WebSocket-Version'    => '13',
            'Origin'                   => self::ORIGIN,
            'Sec-WebSocket-Extensions' => 'permessage-deflate; client_max_window_bits',
        ]);

        self::assertArrayNotHasKey('Sec-WebSocket-Extensions', $response);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private function handshake(): Handshake
    {
        return new Handshake(allowedOrigins: [self::ORIGIN]);
    }

    /** @param \Closure(): mixed $work */
    private function assertRefused(string $fragment, \Closure $work): void
    {
        try {
            $work();
            self::fail("expected a refusal mentioning [{$fragment}]");
        } catch (ProtocolException $e) {
            self::assertStringContainsString($fragment, $e->getMessage());
        }
    }
}
