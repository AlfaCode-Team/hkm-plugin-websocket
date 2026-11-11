// Package protocol is the client-facing JSON, byte-identical to the PHP server.
//
// THE WIRE FORMAT IS A COMPATIBILITY CONTRACT, NOT AN INTERNAL CHOICE
// ------------------------------------------------------------------
// Browsers already written against the PHP server must keep working when an
// operator puts this edge in front of them, so every message name, every field
// name and every field's presence rules match
// Plugins\WebSocket\Application\Services\RealtimeServer exactly. "Nearly the
// same" is worse than different here: a client that can connect but gets
// `subscribed` without a `denied` key fails on a property access, at runtime,
// in a browser, with no server-side evidence.
package protocol

import "encoding/json"

// Subprotocol is negotiated in the handshake. Identical to Handshake::PROTOCOL.
const Subprotocol = "hkm.realtime.v1"

// Inbound is anything the client may send.
//
// Channels is []string rather than a concrete type so that a client sending
// `{"channels": "documents.42"}` — a string, not a list — is a DECODE error
// handled in one place, instead of being silently coerced into a one-element
// list by a hand-rolled parser.
type Inbound struct {
	Type     string   `json:"type"`
	Channels []string `json:"channels"`
}

// Identity is the subset of the PHP Identity the client is told about.
//
// Deliberately small. The edge receives this from PHP and passes it on; it
// never constructs one, because a client told it could choose its own identity
// could choose anybody's. Roles and permissions are NOT included: the client
// has no use for them and echoing an authorization model back to the browser
// invites a front end to make decisions the server has already made.
type Identity struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	Guest    bool   `json:"guest"`
}

// Connected is sent once, immediately after the upgrade.
type Connected struct {
	Type     string   `json:"type"`
	Protocol string   `json:"protocol"`
	Identity Identity `json:"identity"`
}

// Subscribed answers a subscribe request.
//
// BOTH SLICES ARE ALWAYS PRESENT AND NEVER NULL. A client that believes it is
// subscribed and is not waits for ever for an event that was never coming — a
// silent partial success is worse than a flat refusal, which at least surfaces.
//
// In Go that promise needs active defence: a nil slice marshals to JSON `null`,
// and `null.length` throws in the browser. Every constructor here initialises
// both.
type Subscribed struct {
	Type    string   `json:"type"`
	Granted []string `json:"granted"`
	Denied  []string `json:"denied"`
}

// Unsubscribed confirms a removal.
type Unsubscribed struct {
	Type     string   `json:"type"`
	Channels []string `json:"channels"`
	Reason   string   `json:"reason"`
}

// Event is a delivered message.
//
// Channels carries every channel of this client's that matched, so a UI can
// attribute the event without guessing — and it is why a client subscribed to
// two of the published channels receives ONE copy rather than two.
type Event struct {
	Type     string          `json:"type"`
	Channels []string        `json:"channels"`
	Payload  json.RawMessage `json:"payload"`
}

// Error is a refusal.
//
// The message is chosen from a fixed set by the caller and never carries the
// authorizer's reasoning: distinguishing "no such channel" from "exists and is
// not yours" would make the socket an existence oracle for every object in the
// application, probeable one name at a time by anyone who can connect.
type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Pong answers a JSON ping.
//
// A JSON ping exists because BROWSERS CANNOT SEND PROTOCOL PING FRAMES from
// JavaScript — there is no API for it — so a JSON one is the only keepalive a
// web client has. The edge also answers protocol pings, which the websocket
// library does on its own.
type Pong struct {
	Type string `json:"type"`
}

func NewConnected(identity Identity) Connected {
	return Connected{Type: "connected", Protocol: Subprotocol, Identity: identity}
}

// NewSubscribed guarantees both slices are non-nil. See Subscribed.
func NewSubscribed(granted, denied []string) Subscribed {
	if granted == nil {
		granted = []string{}
	}

	if denied == nil {
		denied = []string{}
	}

	return Subscribed{Type: "subscribed", Granted: granted, Denied: denied}
}

func NewUnsubscribed(channels []string, reason string) Unsubscribed {
	if channels == nil {
		channels = []string{}
	}

	return Unsubscribed{Type: "unsubscribed", Channels: channels, Reason: reason}
}

func NewEvent(channels []string, payload json.RawMessage) Event {
	if channels == nil {
		channels = []string{}
	}

	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}

	return Event{Type: "event", Channels: channels, Payload: payload}
}

func NewError(message string) Error {
	return Error{Type: "error", Message: message}
}

func NewPong() Pong {
	return Pong{Type: "pong"}
}
