package bus

import (
	"testing"

	"github.com/AlfaCode-Team/hkm-realtime/internal/channel"
)

// TestTheBroadcastersOwnEnvelopeIsAccepted.
//
// Byte-for-byte what Plugins\WebSocket\Application\Services\Broadcaster
// publishes. If this breaks, the publish side and the delivery side have
// stopped agreeing — and the symptom is a bus with traffic on it and clients
// receiving nothing.
func TestTheBroadcastersOwnEnvelopeIsAccepted(t *testing.T) {
	envelope, dropped := Parse(
		[]byte(`{"channels":["documents.42","collections.7.documents"],"event":{"title":"renamed"}}`),
		channel.Normalise,
	)

	if dropped != "" {
		t.Fatalf("the Broadcaster's envelope was dropped: %s", dropped)
	}

	if len(envelope.Channels) != 2 {
		t.Errorf("channels = %v", envelope.Channels)
	}

	// The event is passed through VERBATIM, never re-encoded: re-encoding would
	// reorder keys and change number formatting, and a client comparing a
	// payload against what it sent would see a different document.
	if string(envelope.Event) != `{"title":"renamed"}` {
		t.Errorf("event = %s, want it verbatim", envelope.Event)
	}
}

// TestMalformedBusInputIsDroppedNotDelivered.
//
// A NATS instance is routinely shared — another service, a staging deployment
// pointed at the wrong host, anyone who reached the port. So a message in
// somebody else's format is the ORDINARY case, not an attack, and it must cost
// a dropped message rather than a crashed subscriber.
func TestMalformedBusInputIsDroppedNotDelivered(t *testing.T) {
	cases := map[string]string{
		"not JSON at all":     `this is not json`,
		"empty":               `{}`,
		"no channels":         `{"event":{"x":1}}`,
		"no event":            `{"channels":["a.1"]}`,
		"channels not a list": `{"channels":"a.1","event":{}}`,
		"event is a string":   `{"channels":["a.1"],"event":"boom"}`,
		"event is a list":     `{"channels":["a.1"],"event":[1,2,3]}`,
		"event is a number":   `{"channels":["a.1"],"event":42}`,
		"event is null":       `{"channels":["a.1"],"event":null}`,
		"only invalid names":  `{"channels":["bad name","documents.*"],"event":{}}`,
		"non-string names":    `{"channels":[null,42],"event":{}}`,
		"empty channel list":  `{"channels":[],"event":{}}`,
		"truncated":           `{"channels":["a.1"],"ev`,
	}

	for label, payload := range cases {
		envelope, dropped := Parse([]byte(payload), channel.Normalise)

		if dropped == "" {
			t.Errorf("[%s] was accepted as %+v; it must be dropped with a reason", label, envelope)
		}
	}
}

// TestAnEmptyEventObjectIsValid — `{}` is a legitimate "something changed,
// come and look" signal, which is exactly the shape an at-most-once bus should
// encourage.
func TestAnEmptyEventObjectIsValid(t *testing.T) {
	envelope, dropped := Parse([]byte(`{"channels":["a.1"],"event":{}}`), channel.Normalise)

	if dropped != "" {
		t.Fatalf("dropped: %s", dropped)
	}

	if string(envelope.Event) != `{}` {
		t.Errorf("event = %s", envelope.Event)
	}
}

// TestInvalidNamesAreFilteredWithoutLosingTheValidOnes.
//
// One bad name in a publish must not lose the rest — a server fanning out to
// ten channels, one of which came from a bad variable, should still reach nine.
func TestInvalidNamesAreFilteredWithoutLosingTheValidOnes(t *testing.T) {
	envelope, dropped := Parse(
		[]byte(`{"channels":["documents.42","bad name","documents.*","","documents.43"],"event":{}}`),
		channel.Normalise,
	)

	if dropped != "" {
		t.Fatalf("dropped: %s", dropped)
	}

	if len(envelope.Channels) != 2 {
		t.Errorf("channels = %v, want the two valid ones", envelope.Channels)
	}
}

func TestDuplicateChannelsAreCollapsed(t *testing.T) {
	envelope, _ := Parse(
		[]byte(`{"channels":["a.1","a.1"," a.1 ","a.2"],"event":{}}`),
		channel.Normalise,
	)

	if len(envelope.Channels) != 2 {
		t.Errorf("channels = %v, want 2 distinct", envelope.Channels)
	}
}

// TestLeadingWhitespaceBeforeTheEventObjectIsTolerated.
//
// A JSON encoder that pretty-prints puts a newline before the `{`. Refusing
// that would make the edge reject a valid envelope depending on how the
// publisher was configured.
func TestLeadingWhitespaceBeforeTheEventObjectIsTolerated(t *testing.T) {
	_, dropped := Parse([]byte("{\"channels\":[\"a.1\"],\"event\":\n   {\"x\":1}}"), channel.Normalise)

	if dropped != "" {
		t.Errorf("pretty-printed JSON was dropped: %s", dropped)
	}
}

// TestABusMessageCannotNameAWildcard.
//
// The important limit on what bus access buys. Even a hostile publisher can
// only name LITERAL channels, so it cannot address every subscriber at once —
// and it still cannot create a subscription, because delivery goes through the
// registry and only the authorizer writes to that.
func TestABusMessageCannotNameAWildcard(t *testing.T) {
	for _, pattern := range []string{">", "*", "documents.>", "documents.*"} {
		_, dropped := Parse(
			[]byte(`{"channels":["`+pattern+`"],"event":{}}`),
			channel.Normalise,
		)

		if dropped == "" {
			t.Errorf("a bus message naming %q was accepted", pattern)
		}
	}
}
