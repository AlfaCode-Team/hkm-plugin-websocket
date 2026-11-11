<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Server;

use Plugins\WebSocket\API\Contracts\Connections;
use Plugins\WebSocket\Domain\Frame;
use Plugins\WebSocket\Domain\Opcode;

/**
 * {@see Connections} over an OpenSwoole WebSocket server.
 *
 * THE SERVER OBJECT IS REACHED DYNAMICALLY, as it is in the telemetry plugin's
 * coroutine storage, and for the same two reasons: naming
 * `OpenSwoole\WebSocket\Server` in a `use` statement would make this file's
 * static analysis depend on an extension that is absent from the machine the
 * tests run on, and it would make the whole plugin look like it requires
 * OpenSwoole when only the server does. The frame codec, the handshake and the
 * registry run anywhere, which is what makes them testable.
 *
 * OPENSWOOLE DOES ITS OWN FRAMING, which is why this class does not call
 * {@see Frame::encode()}.
 *
 * That is worth being explicit about, because it looks like the codec is going
 * unused. `$server->push()` takes a payload and an opcode and writes the frame
 * itself, so handing it `Frame::encode()`'s output would put a second WebSocket
 * header inside the payload — the client would receive a text message whose
 * first bytes are `\x81\x05`. The codec is still the plugin's own, and it is
 * what runs under any transport that hands over raw bytes; here, the extension
 * is the transport and this class translates to its API.
 */
final class SwooleConnections implements Connections
{
    /** OpenSwoole's own opcode constants, which match RFC 6455's values. */
    private const SWOOLE_OPCODE = [
        'text'   => 0x1,
        'binary' => 0x2,
        'close'  => 0x8,
        'ping'   => 0x9,
        'pong'   => 0xA,
    ];

    /** @param object $server an OpenSwoole\WebSocket\Server */
    public function __construct(private readonly object $server) {}

    public function send(int $connectionId, Frame $frame): bool
    {
        // Checked first, because push() to a closed descriptor emits a warning
        // in addition to returning false — and a server shedding a thousand
        // dead connections would write a thousand warnings to the error log
        // before the registry caught up.
        if (!$this->isOpen($connectionId)) {
            return false;
        }

        /** @var callable $push */
        $push = [$this->server, 'push'];

        try {
            return (bool) $push(
                $connectionId,
                $frame->payload,
                self::SWOOLE_OPCODE[$frame->opcode->label()] ?? self::SWOOLE_OPCODE['text'],
            );
        } catch (\Throwable) {
            // A client that vanished between the isOpen() check and the push.
            // Routine on any real network, and not something to raise: the
            // caller reads false as "forget this connection".
            return false;
        }
    }

    public function close(int $connectionId, ?Frame $frame = null): void
    {
        // The courtesy close frame first, so a client learns WHY. Best effort:
        // if it fails, the disconnect below still happens.
        if ($frame !== null && $frame->opcode === Opcode::Close) {
            $this->send($connectionId, $frame);
        }

        /** @var callable $disconnect */
        $disconnect = [$this->server, 'disconnect'];

        try {
            // Attempted even when the send failed — the point of closing is to
            // release the server's own bookkeeping, and a client that has
            // already gone still has an entry here.
            $disconnect($connectionId);
        } catch (\Throwable) {
            // Already gone. Nothing left to release.
        }
    }

    public function isOpen(int $connectionId): bool
    {
        /** @var callable $isEstablished */
        $isEstablished = [$this->server, 'isEstablished'];

        try {
            return (bool) $isEstablished($connectionId);
        } catch (\Throwable) {
            return false;
        }
    }
}
