<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Domain\Presence;

/**
 * One CONNECTION's presence on one channel.
 *
 * A connection, not a user. Two browser tabs are two members with the same
 * `userId`, and the user is "online" for as long as either exists — which is
 * why {@see \Plugins\WebSocket\Application\Services\PresenceService} derives
 * its events from the difference between the users before and after a change
 * rather than from the individual add and remove: closing one of two tabs must
 * not announce that the user left.
 *
 * Stored in the cache as a plain array ({@see self::toArray()}), never as a
 * serialised object. A cache is shared state that something other than this
 * code can write to, and `unserialize()` of a value read from it is the classic
 * object-injection door.
 *
 * Times are epoch seconds the caller supplies; nothing here reads a clock.
 */
final readonly class PresenceMember
{
    public function __construct(
        public string $userId,
        /** The instant this member lapses unless a heartbeat extends it. */
        public int $expiresAt,
        /** 0 when not typing; otherwise the instant the typing indicator lapses. */
        public int $typingUntil = 0,
        /** The record this member is looking at, or null. */
        public ?string $viewing = null,
    ) {}

    public function expired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }

    public function withExpiry(int $expiresAt): self
    {
        return new self($this->userId, $expiresAt, $this->typingUntil, $this->viewing);
    }

    public function withTypingUntil(int $typingUntil): self
    {
        return new self($this->userId, $this->expiresAt, $typingUntil, $this->viewing);
    }

    public function withViewing(?string $viewing): self
    {
        return new self($this->userId, $this->expiresAt, $this->typingUntil, $viewing);
    }

    /** @return array{u: string, e: int, t: int, v: ?string} */
    public function toArray(): array
    {
        return ['u' => $this->userId, 'e' => $this->expiresAt, 't' => $this->typingUntil, 'v' => $this->viewing];
    }

    /**
     * Rebuild from what the cache returned, or null when it is not a member.
     *
     * Null rather than an exception: a corrupt entry is dropped and the channel
     * carries on, because a presence list that throws on one bad row is a
     * presence list that is down for everyone in the channel.
     */
    public static function fromArray(mixed $raw): ?self
    {
        if (!\is_array($raw)
            || !isset($raw['u'], $raw['e'])
            || !\is_string($raw['u'])
            || $raw['u'] === ''
            || !\is_int($raw['e'])) {
            return null;
        }

        $typing  = $raw['t'] ?? 0;
        $viewing = $raw['v'] ?? null;

        return new self(
            $raw['u'],
            $raw['e'],
            \is_int($typing) ? $typing : 0,
            \is_string($viewing) && $viewing !== '' ? $viewing : null,
        );
    }
}
