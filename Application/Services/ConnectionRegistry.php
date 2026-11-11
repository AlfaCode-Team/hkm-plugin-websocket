<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\WebSocket\Domain\Channel;

/**
 * Who is connected, and what each of them is listening to.
 *
 * TWO INDEXES, DELIBERATELY REDUNDANT
 * -----------------------------------
 * `$channels[$connectionId]` and `$subscribers[$channelName]` hold the same
 * facts from both ends, and keeping them in step is the whole job of this class.
 * One index alone will not do, because the two operations have opposite shapes
 * and both are hot:
 *
 *   - a client subscribing or disconnecting needs "what does THIS connection
 *     hold" — without it, unsubscribing means scanning every channel;
 *   - a message being published needs "who holds THIS channel" — without it,
 *     every publish walks every connection and asks whether it cares.
 *
 * The second is the one that decides whether the server works at scale. With
 * ten thousand connections and a message published to a channel two of them
 * hold, the reverse index touches two entries; a scan touches ten thousand, per
 * message, and a busy application publishes thousands per second. That is the
 * difference between a server that idles and one that is pinned at 100% CPU
 * delivering nothing.
 *
 * WHICH MAKES A LEAK HERE WORSE THAN A LEAK
 * -----------------------------------------
 * If {@see self::forget()} removed a connection from `$channels` and not from
 * `$subscribers`, the server would keep a dead id in the fan-out list forever —
 * and the transport will eventually REUSE that id for a new connection. The new
 * client then receives messages for channels the previous occupant of its file
 * descriptor was authorised for, which it never subscribed to and may not be
 * allowed to see. So removal is symmetric, and {@see self::isConsistent()}
 * exists so a test can assert it rather than trusting the reading.
 *
 * THE CAPS ARE NOT TIDINESS. A connection is unauthenticated until it
 * subscribes, and `subscribe` is a string a client sends — so without a cap per
 * connection, one socket can insert as many channel names as it can type, and
 * each one costs an array entry in both indexes. With a cap, the server's memory
 * is bounded by (connections × channels) and both halves are configured.
 */
final class ConnectionRegistry
{
    /**
     * connection id → the channels it holds.
     *
     * @var array<int, array<string, true>>
     */
    private array $channels = [];

    /**
     * channel name → the connections holding it.
     *
     * @var array<string, array<int, true>>
     */
    private array $subscribers = [];

    /** @var array<int, Identity> */
    private array $identities = [];

    public function __construct(
        /** Channels one connection may hold. */
        private readonly int $maxChannelsPerConnection = 64,
        /** Connections this worker will hold. 0 removes the limit. */
        private readonly int $maxConnections = 10_000,
    ) {}

    /**
     * Record a newly-upgraded connection and its identity.
     *
     * Returns false when the worker is full, which the caller answers with a
     * close rather than an exception: a server at capacity is an operating
     * condition, not a fault.
     */
    public function open(int $connectionId, Identity $identity): bool
    {
        if ($this->maxConnections > 0 && \count($this->identities) >= $this->maxConnections
            && !isset($this->identities[$connectionId])) {
            return false;
        }

        $this->identities[$connectionId] ??= $identity;
        $this->channels[$connectionId]   ??= [];

        return true;
    }

    /**
     * Add $channel to $connectionId.
     *
     * Returns false when the connection is unknown or at its channel cap. The
     * caller tells the client which channels were granted and which were not —
     * see the server's `subscribe` handling — because a client that believes it
     * is subscribed and is not will wait forever for an event that was never
     * going to arrive.
     */
    public function subscribe(int $connectionId, Channel $channel): bool
    {
        if (!isset($this->channels[$connectionId])) {
            return false;
        }

        $held = $this->channels[$connectionId];

        // Already held is a success, not a cap violation: a client
        // resubscribing after a reconnect is ordinary, and counting it against
        // the cap would make a flaky network look like an abusive client.
        if (isset($held[$channel->name])) {
            return true;
        }

        if (\count($held) >= $this->maxChannelsPerConnection) {
            return false;
        }

        $this->channels[$connectionId][$channel->name]   = true;
        $this->subscribers[$channel->name][$connectionId] = true;

        return true;
    }

    public function unsubscribe(int $connectionId, Channel $channel): void
    {
        unset(
            $this->channels[$connectionId][$channel->name],
            $this->subscribers[$channel->name][$connectionId],
        );

        // Drop the channel entry once nobody holds it. Without this the
        // subscriber index grows monotonically with every channel ever named —
        // one empty array per document a client ever looked at, for the life of
        // the worker.
        if (($this->subscribers[$channel->name] ?? []) === []) {
            unset($this->subscribers[$channel->name]);
        }
    }

    /** Remove a connection from both indexes. See the class docblock. */
    public function forget(int $connectionId): void
    {
        foreach (array_keys($this->channels[$connectionId] ?? []) as $name) {
            unset($this->subscribers[$name][$connectionId]);

            if (($this->subscribers[$name] ?? []) === []) {
                unset($this->subscribers[$name]);
            }
        }

        unset($this->channels[$connectionId], $this->identities[$connectionId]);
    }

    /**
     * Drop one channel from every connection that holds it.
     *
     * What an application calls when a permission is revoked. The authoriser is
     * only consulted at subscribe time, so this is the mechanism that makes a
     * revocation take effect without waiting for a reconnect — see
     * {@see \Plugins\WebSocket\API\Contracts\ChannelAuthorizer}.
     *
     * @return list<int> the connections that were holding it, so the caller can
     *                   tell them why they stopped receiving anything
     */
    public function revoke(Channel $channel): array
    {
        $affected = array_keys($this->subscribers[$channel->name] ?? []);

        foreach ($affected as $connectionId) {
            unset($this->channels[$connectionId][$channel->name]);
        }

        unset($this->subscribers[$channel->name]);

        return $affected;
    }

    /**
     * The connections to deliver a message on $channel to.
     *
     * @return list<int>
     */
    public function subscribersOf(Channel $channel): array
    {
        return array_keys($this->subscribers[$channel->name] ?? []);
    }

    /**
     * The connections to deliver to across several channels, each one once.
     *
     * De-duplicated, which matters: a client subscribed to both
     * `documents.42` and `collections.7.documents` would otherwise receive two
     * copies of one event — and a UI that appends on receipt shows the row
     * twice.
     *
     * @param  list<Channel> $channels
     * @return list<int>
     */
    public function subscribersOfAny(array $channels): array
    {
        $found = [];

        foreach ($channels as $channel) {
            foreach ($this->subscribers[$channel->name] ?? [] as $connectionId => $_) {
                $found[$connectionId] = true;
            }
        }

        return array_keys($found);
    }

    public function identityOf(int $connectionId): ?Identity
    {
        return $this->identities[$connectionId] ?? null;
    }

    /** @return list<string> the channel names $connectionId holds */
    public function channelsOf(int $connectionId): array
    {
        return array_keys($this->channels[$connectionId] ?? []);
    }

    public function has(int $connectionId): bool
    {
        return isset($this->identities[$connectionId]);
    }

    public function connections(): int
    {
        return \count($this->identities);
    }

    /** Distinct channels with at least one subscriber. */
    public function activeChannels(): int
    {
        return \count($this->subscribers);
    }

    /**
     * Whether the two indexes agree.
     *
     * For tests and for a status command, not for the hot path — it is O(total
     * subscriptions). It exists because the invariant this class is built on is
     * one that a reader cannot verify by inspection: every entry in one index
     * must have its mirror in the other, and the consequence of a missing
     * mirror is a new client receiving a previous client's messages. An
     * assertion is worth more than a comment there.
     */
    public function isConsistent(): bool
    {
        foreach ($this->channels as $connectionId => $names) {
            foreach (array_keys($names) as $name) {
                if (!isset($this->subscribers[$name][$connectionId])) {
                    return false;
                }
            }
        }

        foreach ($this->subscribers as $name => $connectionIds) {
            if ($connectionIds === []) {
                return false;
            }

            foreach (array_keys($connectionIds) as $connectionId) {
                if (!isset($this->channels[$connectionId][$name])) {
                    return false;
                }
            }
        }

        return true;
    }
}
