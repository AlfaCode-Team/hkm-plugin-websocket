// Package bus consumes the envelope the PHP Broadcaster publishes.
//
// THE ENVELOPE IS FIXED BY THE PUBLISHER, NOT CHOSEN HERE
// ------------------------------------------------------
// Plugins\WebSocket\Application\Services\Broadcaster publishes
//
//	{"channels": ["documents.42", …], "event": { … }}
//
// to one subject, with the target list INSIDE the payload rather than one
// subject per application channel. That shape is not an accident and this
// package must not "improve" it: per-channel subjects would need either a
// pattern subscription — and `*` versus `>` versus `#` differ per bus, so the
// syntax of one bus would leak into the port — or a bus round trip per
// subscribe. The cost of the chosen shape is that every edge receives every
// event, including ones none of its clients want, which is a filter here
// instead of a subscription there.
//
// BUS INPUT IS DATA, NEVER INSTRUCTION
// ------------------------------------
// A NATS instance is routinely shared — another service, a staging deployment
// pointed at the wrong host, anyone who reached the port. So a malformed
// message is dropped and the loop continues; it cannot create a subscription,
// and it cannot reach a client that did not already hold the channel, because
// delivery goes through the registry and only the authorizer writes to that.
// The worst a hostile publisher achieves is noise on a channel somebody is
// already entitled to see.
package bus

import (
	"encoding/json"
)

// Envelope is one broadcast.
type Envelope struct {
	Channels []string        `json:"channels"`
	Event    json.RawMessage `json:"event"`
}

// Parse decodes a bus message, or reports why it was dropped.
//
// Returns a reason string rather than an error because every caller does the
// same thing with it — log it at debug and carry on — and an error type would
// invite somebody to return it up a stack that has nowhere to put it.
func Parse(data []byte, valid func(string) string) (Envelope, string) {
	var raw Envelope

	if err := json.Unmarshal(data, &raw); err != nil {
		return Envelope{}, "not JSON"
	}

	if len(raw.Channels) == 0 {
		return Envelope{}, "no channels"
	}

	if len(raw.Event) == 0 {
		return Envelope{}, "no event"
	}

	// The event must be an OBJECT. A bare scalar or a list would reach the
	// client as a `payload` of a shape the contract does not allow, and a
	// browser destructuring it throws.
	trimmed := trimLeadingSpace(raw.Event)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Envelope{}, "event is not an object"
	}

	channels := make([]string, 0, len(raw.Channels))
	seen := make(map[string]struct{}, len(raw.Channels))

	for _, candidate := range raw.Channels {
		name := valid(candidate)
		if name == "" {
			continue
		}

		if _, duplicate := seen[name]; duplicate {
			continue
		}

		seen[name] = struct{}{}
		channels = append(channels, name)
	}

	if len(channels) == 0 {
		return Envelope{}, "no usable channel names"
	}

	return Envelope{Channels: channels, Event: raw.Event}, ""
}

func trimLeadingSpace(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b[i:]
		}
	}

	return nil
}
