// Package server is the HTTP upgrade, the read loop and the fan-out.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"

	"github.com/AlfaCode-Team/hkm-realtime/internal/authz"
	"github.com/AlfaCode-Team/hkm-realtime/internal/bus"
	"github.com/AlfaCode-Team/hkm-realtime/internal/channel"
	"github.com/AlfaCode-Team/hkm-realtime/internal/config"
	"github.com/AlfaCode-Team/hkm-realtime/internal/protocol"
	"github.com/AlfaCode-Team/hkm-realtime/internal/registry"
)

// Authorizer is what the server asks. An interface so the tests can answer
// without a NATS server, and so the failure modes that matter — a timeout, a
// responder that is not running, a malformed reply — are three lines each.
type Authorizer interface {
	Identify(ctx context.Context, creds authz.Credentials) (protocol.Identity, error)
	Authorize(ctx context.Context, creds authz.Credentials, channels []string) (authz.Reply, error)
}

// Server holds the live connections for one process.
type Server struct {
	cfg        config.Config
	registry   *registry.Registry
	authorizer Authorizer
	log        *slog.Logger

	// drain is closed on shutdown. Every read loop watches it so a SIGTERM
	// closes sockets with 1001 Going Away rather than dropping TCP — a client
	// that sees a clean close reconnects immediately, where one that sees a
	// reset waits out its backoff.
	drain     chan struct{}
	drainOnce sync.Once
	wg        sync.WaitGroup
}

func New(cfg config.Config, authorizer Authorizer, log *slog.Logger) *Server {
	return &Server{
		cfg:        cfg,
		registry:   registry.New(cfg.MaxConnections, cfg.MaxChannels, cfg.SendBuffer),
		authorizer: authorizer,
		log:        log,
		drain:      make(chan struct{}),
	}
}

func (s *Server) Registry() *registry.Registry { return s.registry }

// Handler is the upgrade endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.Path, s.upgrade)

	return mux
}

// Shutdown closes every connection cleanly and waits for the read loops.
func (s *Server) Shutdown(ctx context.Context) {
	s.drainOnce.Do(func() { close(s.drain) })

	done := make(chan struct{})

	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		// Deadline reached. The sockets are closed either way when the process
		// exits; waiting longer only delays a deploy.
	}
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// THE ORIGIN CHECK, BEFORE THE UPGRADE. See config.AllowsOrigin.
	//
	// Refused with 403 and a body that does NOT name the allowlist: telling a
	// rejected caller which origins would work hands an attacker the exact
	// string to put in a phishing page's Origin — which they cannot forge from
	// a browser, but can from anything else.
	if !s.cfg.AllowsOrigin(origin) {
		s.log.Warn("websocket.origin.refused",
			"origin", origin,
			"remote", clientIP(r),
			"userAgent", r.Header.Get("User-Agent"))
		http.Error(w, "forbidden origin", http.StatusForbidden)

		return
	}

	// AcceptOptions.OriginPatterns is deliberately NOT used: the library's
	// check is skipped entirely (InsecureSkipVerify) because the decision was
	// already made above, against this application's own allowlist, with its
	// own logging. Two origin checks would mean two places to get it wrong.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{protocol.Subprotocol},
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		s.log.Debug("websocket.accept.failed", "error", err)

		return
	}

	conn.SetReadLimit(s.cfg.MaxMessageBytes)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serve(r, conn)
	}()
}

func (s *Server) serve(r *http.Request, conn *websocket.Conn) {
	creds := authz.Credentials{
		Cookie:        r.Header.Get("Cookie"),
		Authorization: r.Header.Get("Authorization"),
		Token:         r.URL.Query().Get("token"),
		RemoteIP:      clientIP(r),
		UserAgent:     r.Header.Get("User-Agent"),
		Origin:        r.Header.Get("Origin"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	identity, err := s.authorizer.Identify(ctx, creds)
	if err != nil {
		// Identity could not be resolved, so nothing can be authorized. Closed
		// with 1011 rather than accepted as a guest: accepting would present a
		// working socket that denies every subscription, which reads to a
		// client as "I have no permissions" instead of "the server is broken".
		s.log.Error("websocket.identify.failed", "error", err, "remote", creds.RemoteIP)
		_ = conn.Close(websocket.StatusInternalError, "identity unavailable")

		return
	}

	entry := s.registry.Open(identity)
	if entry == nil {
		// 1013 Try Again Later. The right code: a client that sees it backs
		// off and retries, where 1011 reads as a bug and 1008 as a refusal.
		s.log.Warn("websocket.capacity.refused", "connections", s.registry.Count())
		_ = conn.Close(websocket.StatusTryAgainLater, "at capacity")

		return
	}

	defer s.registry.Forget(entry.ID)

	// ONE writer goroutine per connection. The library forbids concurrent
	// writes, and routing everything through a channel also means the fan-out
	// never blocks on a socket.
	go s.write(ctx, conn, entry)

	// A WATCHER, because checking a flag at the top of the read loop is not
	// enough: the loop spends almost all its time BLOCKED inside conn.Read,
	// waiting out the idle timeout, so a shutdown flag it only reads between
	// messages is noticed up to IdleTimeout late — two minutes on the default.
	// Closing the connection is what makes the blocked read return, and it is
	// what turns a deploy from "clients see a TCP reset and wait out their
	// backoff" into "clients see 1001 and reconnect at once".
	go func() {
		select {
		case <-s.drain:
			_ = conn.Close(websocket.StatusGoingAway, "server shutting down")
		case <-entry.Closed():
			_ = conn.Close(websocket.StatusPolicyViolation, "connection dropped")
		case <-ctx.Done():
		}
	}()

	if !s.queue(entry, protocol.NewConnected(identity)) {
		return
	}

	s.read(ctx, conn, entry, creds)
}

// read is the per-connection loop.
func (s *Server) read(ctx context.Context, conn *websocket.Conn, entry *registry.Conn, creds authz.Credentials) {
	for {
		// Not the shutdown check — that is the watcher goroutine's job, because
		// this loop is blocked inside Read almost all the time. This only
		// avoids starting a fresh read after a close we already know about.
		select {
		case <-s.drain:
			return
		case <-entry.Closed():
			return
		default:
		}

		// The idle timeout is enforced per READ, not by a timer: a client that
		// sends nothing for longer than this is gone, and without it a dead
		// TCP connection occupies a slot until the OS notices, which can be
		// hours.
		readCtx, cancel := context.WithTimeout(ctx, s.cfg.IdleTimeout)
		kind, data, err := conn.Read(readCtx)
		cancel()

		if err != nil {
			status := websocket.CloseStatus(err)
			if status == -1 && !errors.Is(err, context.Canceled) {
				s.log.Debug("websocket.read.ended", "id", entry.ID, "error", err)
			}

			return
		}

		if kind != websocket.MessageText {
			// Binary is refused rather than ignored: the protocol is JSON, and
			// silently dropping a binary frame leaves a client waiting for a
			// reply to something the server never acknowledged.
			s.queue(entry, protocol.NewError("this protocol is JSON text; binary frames are not accepted"))

			continue
		}

		s.handle(ctx, entry, creds, data)
	}
}

func (s *Server) handle(ctx context.Context, entry *registry.Conn, creds authz.Credentials, data []byte) {
	var inbound protocol.Inbound

	if err := json.Unmarshal(data, &inbound); err != nil {
		s.queue(entry, protocol.NewError("malformed message"))

		return
	}

	switch inbound.Type {
	case "ping":
		s.queue(entry, protocol.NewPong())

	case "subscribe":
		s.subscribe(ctx, entry, creds, inbound.Channels)

	case "unsubscribe":
		accepted, _ := channel.NormaliseAll(inbound.Channels, 0)
		removed := s.registry.Unsubscribe(entry.ID, accepted)
		s.queue(entry, protocol.NewUnsubscribed(removed, "requested"))

	default:
		s.queue(entry, protocol.NewError("unknown message type"))
	}
}

func (s *Server) subscribe(ctx context.Context, entry *registry.Conn, creds authz.Credentials, requested []string) {
	// Validated HERE, before the round trip. An unauthenticated client must
	// not be able to make the edge flood the PHP authorizer with garbage — that
	// is a client choosing how much work the application does.
	accepted, rejected := channel.NormaliseAll(requested, s.cfg.MaxChannels)

	if len(accepted) == 0 {
		s.queue(entry, protocol.NewSubscribed(nil, rejected))

		return
	}

	reply, err := s.authorizer.Authorize(ctx, creds, accepted)
	if err != nil {
		// Every requested channel is denied. The log says why; the client is
		// told only WHICH, never why — distinguishing "no such channel" from
		// "exists and is not yours" would make this socket an existence oracle
		// for every object in the application.
		s.log.Error("websocket.authorize.failed", "error", err, "id", entry.ID)
	}

	// THE INTERSECTION IS DONE HERE, not inside one Authorizer implementation.
	//
	// It belongs on this side of the seam because it is a guard against a
	// MISBEHAVING RESPONDER, and the server must hold it whatever authorizer it
	// was given — a fake in a test, a future HTTP one, a mistake. Putting it in
	// the NATS client meant swapping the client silently removed it.
	//
	// The responder is trusted to decide, not trusted to be well-formed: a
	// channel it "granted" that the client never asked for would subscribe the
	// connection to something out of thin air.
	granted, missing := intersect(accepted, reply.Granted)

	added, overCap := s.registry.Subscribe(entry.ID, granted)

	// Denials are DERIVED rather than taken from the reply, so a responder that
	// returns neither list cannot produce a subscription that is silently
	// half-made.
	denied := make([]string, 0, len(rejected)+len(missing)+len(overCap))
	denied = append(denied, rejected...)
	denied = append(denied, missing...)
	denied = append(denied, overCap...)

	s.queue(entry, protocol.NewSubscribed(added, denied))
}

// intersect keeps only what was asked for, and derives what was not granted.
func intersect(asked, granted []string) (kept []string, missing []string) {
	allowed := make(map[string]struct{}, len(granted))
	for _, name := range granted {
		allowed[name] = struct{}{}
	}

	kept = make([]string, 0, len(asked))
	missing = make([]string, 0)

	for _, name := range asked {
		if _, ok := allowed[name]; ok {
			kept = append(kept, name)
		} else {
			missing = append(missing, name)
		}
	}

	return kept, missing
}

// write is the single writer for one connection.
func (s *Server) write(ctx context.Context, conn *websocket.Conn, entry *registry.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-entry.Closed():
			return
		case payload, ok := <-entry.Send():
			if !ok {
				return
			}

			writeCtx, cancel := context.WithTimeout(ctx, s.cfg.WriteTimeout)
			err := conn.Write(writeCtx, websocket.MessageText, payload)
			cancel()

			if err != nil {
				entry.Drop()

				return
			}
		}
	}
}

// queue encodes and enqueues, reporting whether the connection is still usable.
//
// A connection whose buffer is full even for a DIRECT reply — its own
// `subscribed` or `pong` — is not keeping up with its own conversation and is
// dropped. Waiting instead would hold the read loop, which is the one goroutine
// that would otherwise notice the socket dying.
func (s *Server) queue(entry *registry.Conn, message any) bool {
	payload, err := json.Marshal(message)
	if err != nil {
		s.log.Error("websocket.encode.failed", "error", err, "id", entry.ID)

		return false
	}

	if !entry.Enqueue(payload) {
		entry.Drop()

		return false
	}

	return true
}

// Deliver fans one bus envelope out to the connections that asked for it.
func (s *Server) Deliver(envelope bus.Envelope) int {
	return s.registry.Deliver(envelope.Channels, func(matched []string) ([]byte, error) {
		return json.Marshal(protocol.NewEvent(matched, envelope.Event))
	})
}

// Revoke drops a channel from every connection holding it, and says so.
//
// What makes a permission change take effect NOW rather than at the next
// reconnect — and the connection is TOLD, because a client silently
// unsubscribed waits for events that are never coming, which is the same
// failure the `denied` list exists to prevent.
func (s *Server) Revoke(name string) int {
	affected := s.registry.Revoke(name)

	for _, entry := range affected {
		s.queue(entry, protocol.NewUnsubscribed([]string{name}, "revoked"))
	}

	return len(affected)
}

// clientIP prefers the first X-Forwarded-For hop, then RemoteAddr.
//
// Trusting XFF unconditionally is wrong when the edge is reachable directly —
// a client can send any value — so this is used for LOGGING and for passing to
// PHP as a hint, never for an authorization decision. PHP is told the origin
// and the credential; what it does with an IP is its business.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
			return first
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}
