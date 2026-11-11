package registry

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
)

func encodeMatched(matched []string) ([]byte, error) {
	return json.Marshal(matched)
}

func TestOpenRespectsTheConnectionCap(t *testing.T) {
	r := New(2, 10, 8)

	if r.Open(nil) == nil || r.Open(nil) == nil {
		t.Fatal("the first two connections must be accepted")
	}

	if r.Open(nil) != nil {
		t.Fatal("the third must be refused: an edge at capacity should refuse NEW clients rather " +
			"than degrade for the ones it already has")
	}

	if r.Count() != 2 {
		t.Errorf("Count = %d, want 2", r.Count())
	}
}

func TestSubscribeRespectsThePerConnectionCap(t *testing.T) {
	r := New(0, 3, 8)
	c := r.Open(nil)

	added, refused := r.Subscribe(c.ID, []string{"a.1", "a.2", "a.3", "a.4", "a.5"})

	if len(added) != 3 {
		t.Errorf("added = %v, want 3", added)
	}

	// Refused, not dropped. A client told it holds three of the five it asked
	// for can act; one told nothing cannot.
	if len(refused) != 2 {
		t.Errorf("refused = %v, want 2", refused)
	}
}

// TestResubscribingIsIdempotent — a client that sends the same subscribe twice
// must not consume two slots of its own cap.
func TestResubscribingIsIdempotent(t *testing.T) {
	r := New(0, 2, 8)
	c := r.Open(nil)

	r.Subscribe(c.ID, []string{"a.1"})
	added, refused := r.Subscribe(c.ID, []string{"a.1"})

	if len(added) != 1 || len(refused) != 0 {
		t.Errorf("added=%v refused=%v; a repeat must be granted, not charged again", added, refused)
	}

	if got := len(r.Subscriptions(c.ID)); got != 1 {
		t.Errorf("the connection holds %d channels, want 1", got)
	}
}

// TestOneCopyForTwoMatchingChannels is why the matched names are collected per
// connection before anything is queued.
//
// Without it, a UI that appends a row on receipt shows it twice — and the
// duplicate looks like the application emitting the event twice, which sends
// somebody debugging the publisher.
func TestOneCopyForTwoMatchingChannels(t *testing.T) {
	r := New(0, 10, 8)
	c := r.Open(nil)

	r.Subscribe(c.ID, []string{"documents.42", "collections.7.documents"})

	delivered := r.Deliver([]string{"documents.42", "collections.7.documents"}, encodeMatched)

	if delivered != 1 {
		t.Errorf("delivered to %d connections, want 1", delivered)
	}

	select {
	case payload := <-c.Send():
		var matched []string
		if err := json.Unmarshal(payload, &matched); err != nil {
			t.Fatal(err)
		}

		// BOTH matching names travel with the one copy, so a client can
		// attribute it without guessing.
		if len(matched) != 2 {
			t.Errorf("matched = %v, want both channels", matched)
		}
	default:
		t.Fatal("nothing was queued")
	}

	select {
	case <-c.Send():
		t.Fatal("a second copy was queued")
	default:
	}
}

func TestDeliveryReachesOnlySubscribers(t *testing.T) {
	r := New(0, 10, 8)
	subscriber := r.Open(nil)
	bystander := r.Open(nil)

	r.Subscribe(subscriber.ID, []string{"documents.42"})
	r.Subscribe(bystander.ID, []string{"documents.99"})

	if n := r.Deliver([]string{"documents.42"}, encodeMatched); n != 1 {
		t.Errorf("delivered to %d, want 1", n)
	}

	select {
	case <-bystander.Send():
		t.Fatal("a connection that never subscribed received the event")
	default:
	}
}

// TestASlowConsumerIsDroppedRatherThanWaitedFor.
//
// The alternative is worse in a way that is easy to miss: blocking on a full
// buffer holds the fan-out goroutine, so ONE client that stopped reading stops
// delivery for every other client on the edge.
func TestASlowConsumerIsDroppedRatherThanWaitedFor(t *testing.T) {
	r := New(0, 10, 2) // a buffer of 2
	slow := r.Open(nil)
	healthy := r.Open(nil)

	r.Subscribe(slow.ID, []string{"busy"})
	r.Subscribe(healthy.ID, []string{"busy"})

	// Nobody reads `slow`, so its buffer fills after two.
	for i := 0; i < 5; i++ {
		r.Deliver([]string{"busy"}, encodeMatched)

		// Keep the healthy one draining, as a real writer goroutine would.
		select {
		case <-healthy.Send():
		default:
		}
	}

	select {
	case <-slow.Closed():
	default:
		t.Fatal("the slow consumer should have been dropped once its buffer filled")
	}

	if r.Dropped() == 0 {
		t.Error("the drop must be counted: a rising count means the app publishes faster than clients read")
	}

	// And the healthy connection is still there and still consistent.
	if r.Count() != 1 {
		t.Errorf("Count = %d, want only the healthy connection", r.Count())
	}

	if !r.IsConsistent() {
		t.Fatal("the indexes must still mirror after a slow consumer is dropped")
	}
}

func TestForgetRemovesEveryTrace(t *testing.T) {
	r := New(0, 10, 8)
	c := r.Open(nil)

	r.Subscribe(c.ID, []string{"a.1", "a.2"})
	r.Forget(c.ID)

	if r.Count() != 0 {
		t.Errorf("Count = %d, want 0", r.Count())
	}

	// The channel index must be empty too, not merely missing the connection.
	// An id left behind here is inherited by the next client to be given that
	// id by the transport.
	if r.Channels() != 0 {
		t.Errorf("Channels = %d, want 0 — a leftover id is inherited by the next client", r.Channels())
	}

	if !r.IsConsistent() {
		t.Fatal("indexes disagree after Forget")
	}
}

func TestRevokeDropsTheChannelFromEveryHolderAndNamesThem(t *testing.T) {
	r := New(0, 10, 8)
	a := r.Open(nil)
	b := r.Open(nil)
	c := r.Open(nil)

	r.Subscribe(a.ID, []string{"documents.42", "other"})
	r.Subscribe(b.ID, []string{"documents.42"})
	r.Subscribe(c.ID, []string{"other"})

	affected := r.Revoke("documents.42")

	if len(affected) != 2 {
		t.Fatalf("affected %d connections, want 2", len(affected))
	}

	// The returned connections are what lets the caller TELL each client. A
	// client silently unsubscribed waits for events that are never coming.
	for _, conn := range affected {
		if conn.ID != a.ID && conn.ID != b.ID {
			t.Errorf("connection %d was not holding the channel", conn.ID)
		}
	}

	// The other subscription survives.
	if len(r.Subscriptions(a.ID)) != 1 {
		t.Error("revoking one channel must not disturb the others")
	}

	if n := r.Deliver([]string{"documents.42"}, encodeMatched); n != 0 {
		t.Errorf("delivered to %d after a revoke, want 0", n)
	}

	if !r.IsConsistent() {
		t.Fatal("indexes disagree after Revoke")
	}
}

// TestTheIndexesStayMirroredUnderRandomOperations is the fuzz.
//
// A connection id left in the channel index after its socket closed is
// invisible — until the transport REUSES that id, at which point a new client
// inherits the previous occupant's subscriptions and starts receiving somebody
// else's events. No single-operation test finds that; a few thousand random
// ones do.
func TestTheIndexesStayMirroredUnderRandomOperations(t *testing.T) {
	r := New(0, 8, 4)
	rng := rand.New(rand.NewSource(1))

	live := []*Conn{}
	names := []string{"a.1", "a.2", "b.1", "b.2", "c.1", "shared"}

	for step := 0; step < 4000; step++ {
		switch rng.Intn(6) {
		case 0:
			if c := r.Open(nil); c != nil {
				live = append(live, c)
			}

		case 1:
			if len(live) > 0 {
				c := live[rng.Intn(len(live))]
				r.Subscribe(c.ID, []string{names[rng.Intn(len(names))]})
			}

		case 2:
			if len(live) > 0 {
				c := live[rng.Intn(len(live))]
				r.Unsubscribe(c.ID, []string{names[rng.Intn(len(names))]})
			}

		case 3:
			if len(live) > 0 {
				i := rng.Intn(len(live))
				r.Forget(live[i].ID)
				live = append(live[:i], live[i+1:]...)
			}

		case 4:
			r.Revoke(names[rng.Intn(len(names))])

		case 5:
			// Deliveries drop slow consumers, which mutates both indexes from
			// inside the fan-out — the path most likely to leave them
			// disagreeing.
			r.Deliver([]string{names[rng.Intn(len(names))]}, encodeMatched)
		}

		if !r.IsConsistent() {
			t.Fatalf("the indexes disagreed after step %d", step)
		}
	}
}

func TestDeliverSkipsAConnectionThatIsAlreadyDropped(t *testing.T) {
	r := New(0, 10, 8)
	c := r.Open(nil)
	r.Subscribe(c.ID, []string{"a.1"})

	c.Drop()

	// Dropped but not yet Forgotten — the window between a read loop noticing
	// and the deferred cleanup running. Enqueue must refuse.
	if c.Enqueue([]byte("x")) {
		t.Error("a dropped connection must not accept more payloads")
	}
}

func TestEnqueueReportsAFullBufferRatherThanBlocking(t *testing.T) {
	r := New(0, 10, 1)
	c := r.Open(nil)

	if !c.Enqueue([]byte("first")) {
		t.Fatal("the first payload fits")
	}

	if c.Enqueue([]byte("second")) {
		t.Fatal("a full buffer must report false, never block")
	}
}

func TestSubscribeToAnUnknownConnectionRefusesEverything(t *testing.T) {
	r := New(0, 10, 8)

	added, refused := r.Subscribe(99999, []string{"a.1"})

	if len(added) != 0 || len(refused) != 1 {
		t.Errorf("added=%v refused=%v; an unknown id must grant nothing", added, refused)
	}
}

func BenchmarkDeliverToManySubscribers(b *testing.B) {
	r := New(0, 10, 1024)

	for i := 0; i < 10_000; i++ {
		c := r.Open(nil)
		r.Subscribe(c.ID, []string{fmt.Sprintf("shard.%d", i%100), "broadcast"})

		// Drain continuously so the buffers never fill.
		go func(conn *Conn) {
			for range conn.Send() {
			}
		}(c)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r.Deliver([]string{"broadcast"}, encodeMatched)
	}
}
