<?php

declare(strict_types=1);

namespace Plugins\WebSocket\API\Contracts;

use Plugins\WebSocket\Domain\Frame;

/**
 * Sending to a connection, abstracted away from the transport.
 *
 * WHY THE SERVER'S LOGIC DOES NOT TOUCH A SOCKET
 * ----------------------------------------------
 * {@see \Plugins\WebSocket\Application\Services\RealtimeServer} decides who may
 * subscribe to what, which is the part of this plugin where a mistake is a
 * security incident rather than a dropped message. That decision must be
 * testable, and it cannot be if making it requires a listening socket, an
 * OpenSwoole worker, and a real client to connect.
 *
 * So the server core takes this interface and an implementation does the
 * writing — `OpenSwoole\WebSocket\Server::push()` in production, a recording
 * array in the tests. The authorisation tests then assert exactly what was sent
 * to whom, with no network at all, which is the only way to check the case that
 * matters most: that nothing was sent to a connection that was not authorised.
 */
interface Connections
{
    /**
     * Write one frame to one connection.
     *
     * Returns false when the connection is gone — which is ordinary rather than
     * exceptional, because a client can disconnect between the registry being
     * read and the write being attempted. The caller treats false as "forget
     * this connection" rather than as an error.
     */
    public function send(int $connectionId, Frame $frame): bool;

    /**
     * Close a connection, optionally after a final frame.
     *
     * An implementation must attempt the close even when {@see self::send()}
     * has just failed: the point of closing is to release the server's own
     * bookkeeping, and a client that has already vanished still has an entry
     * here.
     */
    public function close(int $connectionId, ?Frame $frame = null): void;

    /** Whether the transport still considers this connection open. */
    public function isOpen(int $connectionId): bool;
}
