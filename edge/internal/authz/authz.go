// Package authz asks the PHP application who may subscribe to what.
//
// THE EDGE DOES NOT DECIDE. THAT IS THE POINT OF THIS PACKAGE.
// -----------------------------------------------------------
// The authorization rule — which identity may see which channel — lives in the
// project's ChannelAuthorizer, in PHP, next to the data it has to query. This
// edge has no database, no session store and no business model, and giving it
// any of those would mean the rule had two implementations. Two
// implementations of an authorization rule is how a channel becomes readable on
// one path and not the other.
//
// So the edge sends the raw credential material it received and the channel
// names it was asked for, and PHP answers with an identity and two lists. Over
// NATS request/reply, which the bus is already there for.
//
// IT IS ONE ROUND TRIP PER SUBSCRIBE, NOT PER MESSAGE
// ---------------------------------------------------
// The same budget the PHP server already spends: RealtimeServer consults the
// authorizer once per channel per subscription and never per delivery, because
// a store round trip in front of every message would not survive. Nothing here
// changes that arithmetic — it moves the same call onto a bus.
//
// THE EDGE NEVER PARSES A CREDENTIAL
// ----------------------------------
// Cookies, bearer tokens and query tokens are forwarded as opaque strings. The
// edge cannot validate a PHP session and must not try: a second session parser
// would be a second place for a session to be considered valid, and the
// interesting bugs in session handling are all in the parsing.
//
// FAILURE IS A DENIAL, NEVER A GRANT
// ----------------------------------
// A timeout, an unreachable bus, a malformed reply — every one of them denies.
// That is the only safe direction, and it is worth stating because the
// convenient direction is so obviously the other one: an edge that granted on
// error would hand out every requested channel the moment PHP stopped
// answering, which is exactly when nobody is watching.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/AlfaCode-Team/hkm-realtime/internal/protocol"
)

// Credentials is what arrived with the upgrade request, unparsed.
type Credentials struct {
	Cookie        string `json:"cookie,omitempty"`
	Authorization string `json:"authorization,omitempty"`
	Token         string `json:"token,omitempty"`
	RemoteIP      string `json:"remoteIp,omitempty"`
	UserAgent     string `json:"userAgent,omitempty"`
	Origin        string `json:"origin,omitempty"`
}

// Request is the body published to the authorize subject.
type Request struct {
	Credentials Credentials `json:"credentials"`
	Channels    []string    `json:"channels"`
}

// Reply is what PHP answers.
type Reply struct {
	Identity protocol.Identity `json:"identity"`
	Granted  []string          `json:"granted"`
	Denied   []string          `json:"denied"`
}

// ErrUnavailable means nobody answered. Distinguished from a denial so the
// operator sees "the responder is down" rather than "your rules refused this".
var ErrUnavailable = errors.New("no realtime authorizer answered")

// Client asks a PHP responder.
type Client struct {
	conn    *nats.Conn
	subject string
	timeout time.Duration
}

func New(conn *nats.Conn, subject string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	return &Client{conn: conn, subject: subject, timeout: timeout}
}

// Identify resolves who a connection belongs to, asking about no channels.
//
// The same subject and the same handler as Authorize — an empty channel list is
// an identify-only call. One responder rather than two means the identity a
// subscribe is checked against cannot be resolved by different code from the
// identity the client was told about.
func (c *Client) Identify(ctx context.Context, creds Credentials) (protocol.Identity, error) {
	reply, err := c.ask(ctx, Request{Credentials: creds, Channels: []string{}})
	if err != nil {
		return protocol.Identity{Guest: true}, err
	}

	return reply.Identity, nil
}

// Authorize asks which of channels this connection may have.
//
// On ANY error every requested channel is denied. See the package docblock.
func (c *Client) Authorize(ctx context.Context, creds Credentials, channels []string) (Reply, error) {
	if len(channels) == 0 {
		return Reply{Granted: []string{}, Denied: []string{}}, nil
	}

	reply, err := c.ask(ctx, Request{Credentials: creds, Channels: channels})
	if err != nil {
		denied := make([]string, len(channels))
		copy(denied, channels)

		return Reply{Identity: protocol.Identity{Guest: true}, Granted: []string{}, Denied: denied}, err
	}

	// NO intersection here, deliberately. Narrowing the reply to what was
	// asked for is a guard against a misbehaving responder, and it belongs to
	// the SERVER so it holds for every Authorizer implementation — see
	// server.subscribe. Doing it in both places would mean the next
	// implementation of this interface quietly dropped the guard.
	if reply.Granted == nil {
		reply.Granted = []string{}
	}

	if reply.Denied == nil {
		reply.Denied = []string{}
	}

	return reply, nil
}

func (c *Client) ask(ctx context.Context, request Request) (Reply, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Reply{}, fmt.Errorf("encoding the authorize request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	message, err := c.conn.RequestWithContext(ctx, c.subject, body)
	if err != nil {
		// NoResponders is the useful one: the bus is healthy and nothing is
		// subscribed, which means `realtime:authorize` is not running. That is
		// a different fix from a timeout and deserves a different message.
		if errors.Is(err, nats.ErrNoResponders) {
			return Reply{}, fmt.Errorf("%w on %s (is `hkm cli realtime:authorize` running?)", ErrUnavailable, c.subject)
		}

		return Reply{}, fmt.Errorf("asking %s: %w", c.subject, err)
	}

	var reply Reply
	if err := json.Unmarshal(message.Data, &reply); err != nil {
		return Reply{}, fmt.Errorf("decoding the authorize reply: %w", err)
	}

	return reply, nil
}
