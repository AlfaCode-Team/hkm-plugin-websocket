// Package registry holds the live connections and which channels each wants.
//
// TWO MIRRORED INDEXES, AND KEEPING THEM MIRRORED IS THE WHOLE JOB
// ---------------------------------------------------------------
//
//	byConn:    id      -> set of channels   (what to drop when a socket closes)
//	byChannel: channel -> set of ids        (who to deliver to, without a scan)
//
// One index would do for correctness and neither direction can be derived
// cheaply from the other at the rates that matter: a delivery to a channel with
// three subscribers must not walk 50,000 connections, and a close must not walk
// every channel.
//
// The failure when they disagree is specific and nasty. An id left in byChannel
// after its socket closed is a delivery to a connection that no longer exists —
// harmless on its own — but connection ids are REUSED by the transport, so the
// next client to arrive inherits the previous occupant's subscriptions and
// starts receiving somebody else's events. Which is why IsConsistent exists and
// why the tests fuzz it.
//
// EVERY DELIVERY GOES THROUGH A PER-CONNECTION BUFFERED CHANNEL, never a direct
// socket write. The websocket library forbids concurrent writes, and more
// importantly a client that has stopped reading must not be able to block the
// fan-out goroutine — one stalled consumer would hold up delivery to everybody
// else. A full buffer means that client is dropped; see Deliver.
package registry

import (
	"sync"
)

// Conn is one live connection, as the registry sees it.
type Conn struct {
	ID       uint64
	Identity any

	// send is buffered. Its depth is how far behind a client may fall before
	// it is disconnected as a slow consumer.
	send chan []byte

	// closeOnce guards Drop, which may be called from the read loop, the
	// fan-out goroutine and the shutdown path at the same time.
	closeOnce sync.Once
	closed    chan struct{}
}

// Registry is safe for concurrent use.
type Registry struct {
	mu        sync.RWMutex
	byConn    map[uint64]map[string]struct{}
	conns     map[uint64]*Conn
	byChannel map[string]map[uint64]struct{}

	maxConnections int
	maxChannels    int
	sendBuffer     int

	nextID uint64

	// dropped counts slow consumers disconnected. A number worth watching: a
	// rising count means the application publishes faster than clients read.
	dropped uint64
}

func New(maxConnections, maxChannels, sendBuffer int) *Registry {
	if sendBuffer <= 0 {
		sendBuffer = 64
	}

	return &Registry{
		byConn:         make(map[uint64]map[string]struct{}),
		conns:          make(map[uint64]*Conn),
		byChannel:      make(map[string]map[uint64]struct{}),
		maxConnections: maxConnections,
		maxChannels:    maxChannels,
		sendBuffer:     sendBuffer,
	}
}

// Open registers a connection, or returns nil when the cap is reached.
//
// Nil rather than an error: the caller's response is to close the socket with
// 1013 Try Again Later, which is a protocol answer rather than an exception.
// Refusing at the cap is what keeps an overloaded edge refusing NEW clients
// instead of degrading for the ones it already has.
func (r *Registry) Open(identity any) *Conn {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.maxConnections > 0 && len(r.conns) >= r.maxConnections {
		return nil
	}

	r.nextID++

	conn := &Conn{
		ID:       r.nextID,
		Identity: identity,
		send:     make(chan []byte, r.sendBuffer),
		closed:   make(chan struct{}),
	}

	r.conns[conn.ID] = conn
	r.byConn[conn.ID] = make(map[string]struct{})

	return conn
}

// Send is the connection's outbound queue, read by its single writer goroutine.
func (c *Conn) Send() <-chan []byte { return c.send }

// Closed fires once, when the connection is dropped.
func (c *Conn) Closed() <-chan struct{} { return c.closed }

// Drop marks the connection finished. Idempotent and safe from any goroutine.
func (c *Conn) Drop() {
	c.closeOnce.Do(func() { close(c.closed) })
}

// Enqueue queues one payload without blocking.
//
// Reports false when the connection is closed OR its buffer is full. Never
// blocks, because every caller is either the fan-out goroutine — which must not
// be held up by one slow client — or a read loop that has other work to do.
// A full buffer means this client is not keeping up, and the caller's answer is
// to drop it rather than wait.
func (c *Conn) Enqueue(payload []byte) bool {
	select {
	case <-c.closed:
		return false
	default:
	}

	select {
	case c.send <- payload:
		return true
	default:
		return false
	}
}

// Count returns the live connection count.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.conns)
}

// Channels returns the number of distinct channels with at least one subscriber.
func (r *Registry) Channels() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.byChannel)
}

// Dropped returns how many slow consumers have been disconnected.
func (r *Registry) Dropped() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.dropped
}

// Subscribe adds channels to a connection, returning those it now holds.
//
// The per-connection cap is enforced HERE and not only at the edge of the
// protocol, because this is the only place that knows how many the connection
// already has — a client can send ten subscribe messages of ten channels each.
func (r *Registry) Subscribe(id uint64, channels []string) (added []string, refused []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	added = []string{}
	refused = []string{}

	held, ok := r.byConn[id]
	if !ok {
		return added, channels
	}

	for _, name := range channels {
		if _, already := held[name]; already {
			added = append(added, name)
			continue
		}

		if r.maxChannels > 0 && len(held) >= r.maxChannels {
			refused = append(refused, name)
			continue
		}

		held[name] = struct{}{}

		if r.byChannel[name] == nil {
			r.byChannel[name] = make(map[uint64]struct{})
		}

		r.byChannel[name][id] = struct{}{}
		added = append(added, name)
	}

	return added, refused
}

// Unsubscribe removes channels from a connection.
func (r *Registry) Unsubscribe(id uint64, channels []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := []string{}

	held, ok := r.byConn[id]
	if !ok {
		return removed
	}

	for _, name := range channels {
		if _, has := held[name]; !has {
			continue
		}

		delete(held, name)
		r.detach(name, id)
		removed = append(removed, name)
	}

	return removed
}

// Forget removes a connection and every trace of it from both indexes.
func (r *Registry) Forget(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if conn, ok := r.conns[id]; ok {
		conn.Drop()
		delete(r.conns, id)
	}

	for name := range r.byConn[id] {
		r.detach(name, id)
	}

	delete(r.byConn, id)
}

// Revoke drops one channel from every connection holding it.
//
// What makes a permission change take effect NOW rather than at the next
// reconnect. Without it, an authorizer consulted once per subscription means a
// revoked grant keeps delivering for as long as the socket stays open — which
// for a realtime connection is hours.
// Returns the affected connections so the caller can tell each one — a client
// that is silently unsubscribed waits for events that will never come, which is
// the same silent-partial-success failure the `denied` list exists to avoid.
func (r *Registry) Revoke(channel string) []*Conn {
	r.mu.Lock()
	defer r.mu.Unlock()

	affected := []*Conn{}

	for id := range r.byChannel[channel] {
		delete(r.byConn[id], channel)

		if conn, ok := r.conns[id]; ok {
			affected = append(affected, conn)
		}
	}

	delete(r.byChannel, channel)

	return affected
}

// Deliver queues payload to every connection subscribed to any of channels.
//
// Returns how many connections received it. A connection on two of the named
// channels gets ONE copy — which is why the matched names are collected per
// connection before anything is queued.
//
// A connection whose buffer is FULL is dropped rather than waited for. That is
// the slow-consumer decision, and the alternative is worse in a way that is
// easy to miss: blocking here holds the fan-out goroutine, so one client that
// stopped reading stops delivery for every other client on the edge.
func (r *Registry) Deliver(channels []string, encode func(matched []string) ([]byte, error)) int {
	r.mu.Lock()

	matches := make(map[uint64][]string)

	for _, name := range channels {
		for id := range r.byChannel[name] {
			matches[id] = append(matches[id], name)
		}
	}

	type target struct {
		conn    *Conn
		matched []string
	}

	targets := make([]target, 0, len(matches))

	for id, matched := range matches {
		if conn, ok := r.conns[id]; ok {
			targets = append(targets, target{conn: conn, matched: matched})
		}
	}

	r.mu.Unlock()

	delivered := 0
	var slow []uint64

	for _, t := range targets {
		payload, err := encode(t.matched)
		if err != nil {
			continue
		}

		select {
		case t.conn.send <- payload:
			delivered++
		default:
			// Full. This client is behind and will not catch up while we hold
			// the fan-out; dropping it protects everybody else.
			slow = append(slow, t.conn.ID)
			t.conn.Drop()
		}
	}

	if len(slow) > 0 {
		r.mu.Lock()
		r.dropped += uint64(len(slow))
		r.mu.Unlock()

		for _, id := range slow {
			r.Forget(id)
		}
	}

	return delivered
}

// Subscriptions returns a copy of what a connection holds.
func (r *Registry) Subscriptions(id uint64) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	held := make([]string, 0, len(r.byConn[id]))

	for name := range r.byConn[id] {
		held = append(held, name)
	}

	return held
}

// IsConsistent reports whether the two indexes still mirror each other.
//
// Not a debug aid. The failure it catches — an id left in byChannel after its
// connection went away — is invisible until the transport REUSES that id, at
// which point a new client silently inherits the previous occupant's
// subscriptions. The tests fuzz thousands of random operations against this.
func (r *Registry) IsConsistent() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, held := range r.byConn {
		for name := range held {
			if _, ok := r.byChannel[name][id]; !ok {
				return false
			}
		}
	}

	for name, ids := range r.byChannel {
		if len(ids) == 0 {
			// An empty set must be deleted, not left behind: otherwise the
			// channel count grows for ever on a busy edge.
			return false
		}

		for id := range ids {
			if _, ok := r.byConn[id][name]; !ok {
				return false
			}
		}
	}

	return true
}

// detach removes id from a channel's set, deleting the set when it empties.
// Caller holds the write lock.
func (r *Registry) detach(name string, id uint64) {
	ids := r.byChannel[name]
	if ids == nil {
		return
	}

	delete(ids, id)

	if len(ids) == 0 {
		delete(r.byChannel, name)
	}
}
