package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/AlfaCode-Team/hkm-realtime/internal/authz"
	"github.com/AlfaCode-Team/hkm-realtime/internal/bus"
	"github.com/AlfaCode-Team/hkm-realtime/internal/channel"
	"github.com/AlfaCode-Team/hkm-realtime/internal/config"
	"github.com/AlfaCode-Team/hkm-realtime/internal/protocol"
)

// These run against a REAL httptest server and a REAL websocket client, so the
// handshake, the subprotocol negotiation, the framing and the close codes are
// the library's actual behaviour rather than an assumption about it. Only the
// AUTHORIZER is faked — which is the point, since the real one is PHP.

type fakeAuthorizer struct {
	identity protocol.Identity
	allow    map[string]bool
	fail     error
	asked    [][]string
	delay    time.Duration
	// grants it was never asked for, to test that the edge intersects.
	extra []string
}

func (f *fakeAuthorizer) Identify(context.Context, authz.Credentials) (protocol.Identity, error) {
	if f.fail != nil {
		return protocol.Identity{Guest: true}, f.fail
	}

	return f.identity, nil
}

func (f *fakeAuthorizer) Authorize(ctx context.Context, _ authz.Credentials, channels []string) (authz.Reply, error) {
	f.asked = append(f.asked, channels)

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return authz.Reply{Granted: []string{}, Denied: channels}, ctx.Err()
		}
	}

	if f.fail != nil {
		return authz.Reply{Granted: []string{}, Denied: channels}, f.fail
	}

	granted := []string{}
	denied := []string{}

	for _, name := range channels {
		if f.allow[name] {
			granted = append(granted, name)
		} else {
			denied = append(denied, name)
		}
	}

	granted = append(granted, f.extra...)

	return authz.Reply{Identity: f.identity, Granted: granted, Denied: denied}, nil
}

func testConfig() config.Config {
	return config.Config{
		Path:             "/realtime",
		Origins:          []string{"https://app.example.com"},
		RequireOrigin:    true,
		MaxConnections:   10,
		MaxChannels:      4,
		MaxMessageBytes:  1 << 20,
		SendBuffer:       16,
		IdleTimeout:      5 * time.Second,
		WriteTimeout:     2 * time.Second,
		AuthorizeTimeout: time.Second,
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// dial opens a real websocket against a real server.
func dial(t *testing.T, srv *Server, origin string) (*httptest.Server, *websocket.Conn) {
	t.Helper()

	http := httptest.NewServer(srv.Handler())
	t.Cleanup(http.Close)

	header := make(map[string][]string)
	if origin != "" {
		header["Origin"] = []string{origin}
	}

	conn, resp, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(http.URL, "http")+"/realtime",
		&websocket.DialOptions{
			HTTPHeader:   header,
			Subprotocols: []string{protocol.Subprotocol},
		})
	if err != nil {
		if resp != nil {
			t.Fatalf("dial failed with HTTP %d: %v", resp.StatusCode, err)
		}

		t.Fatalf("dial failed: %v", err)
	}

	t.Cleanup(func() { _ = conn.CloseNow() })

	return http, conn
}

func readJSON(t *testing.T, conn *websocket.Conn, into any) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	kind, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if kind != websocket.MessageText {
		t.Fatalf("expected a text frame, got %v", kind)
	}

	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
}

func writeJSON(t *testing.T, conn *websocket.Conn, message any) {
	t.Helper()

	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

// ── The Origin check, over a real handshake ─────────────────────────────────

// TestADisallowedOriginIsRefusedWithoutUpgrading.
//
// 403 BEFORE the upgrade, so the socket never exists. And the body must not
// name the allowlist: telling a rejected caller which origins would work hands
// a non-browser client the exact string to send.
func TestADisallowedOriginIsRefusedWithoutUpgrading(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())
	http1 := httptest.NewServer(srv.Handler())
	defer http1.Close()

	req, _ := http.NewRequest(http.MethodGet, http1.URL+"/realtime", nil)
	req.Header.Set("Origin", "https://app.example.com.attacker.net")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "app.example.com") {
		t.Error("the refusal must not name the allowlist")
	}
}

func TestAnAllowedOriginCompletesTheHandshakeAndNegotiatesTheSubprotocol(t *testing.T) {
	auth := &fakeAuthorizer{identity: protocol.Identity{UserID: "user-1", TenantID: "tenant-1"}}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	if conn.Subprotocol() != protocol.Subprotocol {
		t.Errorf("subprotocol = %q, want %q", conn.Subprotocol(), protocol.Subprotocol)
	}

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	if connected.Type != "connected" {
		t.Errorf("first message type = %q, want connected", connected.Type)
	}

	if connected.Identity.UserID != "user-1" {
		t.Errorf("identity = %+v; it must come from the authorizer, never from the client", connected.Identity)
	}
}

// ── Subscribing ─────────────────────────────────────────────────────────────

func TestSubscribeReportsGrantedAndDeniedAndBothAreAlwaysArrays(t *testing.T) {
	auth := &fakeAuthorizer{allow: map[string]bool{"documents.42": true}}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{
		"type":     "subscribe",
		"channels": []string{"documents.42", "documents.99"},
	})

	// Read the RAW bytes, because the thing being asserted is the JSON shape:
	// a nil slice in Go marshals to `null`, and `denied.length` on null throws
	// in a browser.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(raw), `"granted":[`) || !strings.Contains(string(raw), `"denied":[`) {
		t.Fatalf("both keys must be present as ARRAYS, got %s", raw)
	}

	var reply protocol.Subscribed
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatal(err)
	}

	if len(reply.Granted) != 1 || reply.Granted[0] != "documents.42" {
		t.Errorf("granted = %v", reply.Granted)
	}

	if len(reply.Denied) != 1 || reply.Denied[0] != "documents.99" {
		t.Errorf("denied = %v", reply.Denied)
	}
}

// TestADenialNeverExplainsItself.
//
// Distinguishing "no such channel" from "exists and is not yours" would make
// the socket an existence oracle for every object in the application, probeable
// one name at a time by anyone who can connect.
func TestADenialNeverExplainsItself(t *testing.T) {
	auth := &fakeAuthorizer{allow: map[string]bool{}}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{"type": "subscribe", "channels": []string{"documents.404"}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}

	body := strings.ToLower(string(raw))

	for _, leak := range []string{"forbid", "permission", "owner", "not found", "missing", "unauthor", "reason", "because"} {
		if strings.Contains(body, leak) {
			t.Errorf("the refusal leaked %q: %s", leak, raw)
		}
	}
}

// TestAMalformedChannelNeverReachesTheAuthorizer.
//
// An unauthenticated client must not be able to make the edge flood the PHP
// authorizer with garbage — that is a client choosing how much work the
// application does.
func TestAMalformedChannelNeverReachesTheAuthorizer(t *testing.T) {
	auth := &fakeAuthorizer{allow: map[string]bool{}}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{
		"type":     "subscribe",
		"channels": []string{"bad name", "documents.*", "", strings.Repeat("x", 500)},
	})

	var reply protocol.Subscribed
	readJSON(t, conn, &reply)

	if len(reply.Granted) != 0 {
		t.Errorf("granted = %v, want none", reply.Granted)
	}

	if len(reply.Denied) != 4 {
		t.Errorf("denied = %v, want all four reported", reply.Denied)
	}

	if len(auth.asked) != 0 {
		t.Errorf("the authorizer was asked about %v; malformed names must be refused locally", auth.asked)
	}
}

// TestAFailedAuthorizerDeniesEverything — never grants. The convenient
// direction is so obviously the other one that it is worth a test: an edge that
// granted on error would hand out every requested channel the moment PHP
// stopped answering, which is exactly when nobody is watching.
func TestAFailedAuthorizerDeniesEverything(t *testing.T) {
	auth := &fakeAuthorizer{fail: authz.ErrUnavailable, allow: map[string]bool{"documents.42": true}}
	srv := New(testConfig(), auth, quietLogger())
	cfg := testConfig()
	_ = cfg

	// Identify fails too, so the connection is closed rather than accepted as
	// a guest that denies everything — which would read to a client as "I have
	// no permissions" instead of "the server is broken".
	http1 := httptest.NewServer(srv.Handler())
	defer http1.Close()

	conn, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(http1.URL, "http")+"/realtime",
		&websocket.DialOptions{
			HTTPHeader:   map[string][]string{"Origin": {"https://app.example.com"}},
			Subprotocols: []string{protocol.Subprotocol},
		})
	if err != nil {
		t.Fatalf("the upgrade itself should succeed: %v", err)
	}
	defer conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, readErr := conn.Read(ctx)
	if readErr == nil {
		t.Fatal("the connection must be closed when identity cannot be resolved")
	}

	if status := websocket.CloseStatus(readErr); status != websocket.StatusInternalError {
		t.Errorf("close status = %v, want 1011 Internal Error", status)
	}
}

// TestTheEdgeIntersectsTheAuthorizersAnswerWithTheRequest.
//
// The responder is trusted to DECIDE, not trusted to be well-formed. A channel
// it "granted" that the client never asked for would subscribe the connection
// to something out of thin air.
func TestTheEdgeIntersectsTheAuthorizersAnswerWithTheRequest(t *testing.T) {
	auth := &fakeAuthorizer{
		allow: map[string]bool{"documents.42": true},
		extra: []string{"admin.secrets"},
	}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{"type": "subscribe", "channels": []string{"documents.42"}})

	var reply protocol.Subscribed
	readJSON(t, conn, &reply)

	for _, name := range reply.Granted {
		if name == "admin.secrets" {
			t.Fatal("a channel the client never asked for was granted")
		}
	}

	if len(reply.Granted) != 1 {
		t.Errorf("granted = %v, want only documents.42", reply.Granted)
	}
}

func TestThePerConnectionChannelCapIsEnforced(t *testing.T) {
	allow := map[string]bool{}
	for _, name := range []string{"a.1", "a.2", "a.3", "a.4", "a.5", "a.6"} {
		allow[name] = true
	}

	srv := New(testConfig(), &fakeAuthorizer{allow: allow}, quietLogger()) // MaxChannels 4

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{
		"type":     "subscribe",
		"channels": []string{"a.1", "a.2", "a.3", "a.4", "a.5", "a.6"},
	})

	var reply protocol.Subscribed
	readJSON(t, conn, &reply)

	if len(reply.Granted) != 4 {
		t.Errorf("granted = %v, want 4 (the cap)", reply.Granted)
	}

	if len(reply.Denied) != 2 {
		t.Errorf("denied = %v, want the 2 over the cap", reply.Denied)
	}
}

// ── Delivery ────────────────────────────────────────────────────────────────

// TestABusEventReachesOnlyTheSubscriber — the whole point of the edge.
func TestABusEventReachesOnlyTheSubscriber(t *testing.T) {
	auth := &fakeAuthorizer{allow: map[string]bool{"documents.42": true}}
	srv := New(testConfig(), auth, quietLogger())

	_, subscriber := dial(t, srv, "https://app.example.com")
	_, bystander := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, subscriber, &connected)
	readJSON(t, bystander, &connected)

	writeJSON(t, subscriber, map[string]any{"type": "subscribe", "channels": []string{"documents.42"}})

	var reply protocol.Subscribed
	readJSON(t, subscriber, &reply)

	// The exact envelope the PHP Broadcaster publishes.
	envelope, dropped := bus.Parse(
		[]byte(`{"channels":["documents.42"],"event":{"title":"renamed"}}`),
		channel.Normalise,
	)
	if dropped != "" {
		t.Fatalf("the Broadcaster's own envelope was dropped: %s", dropped)
	}

	if n := srv.Deliver(envelope); n != 1 {
		t.Fatalf("delivered to %d connections, want 1", n)
	}

	var event protocol.Event
	readJSON(t, subscriber, &event)

	if event.Type != "event" {
		t.Errorf("type = %q", event.Type)
	}

	if len(event.Channels) != 1 || event.Channels[0] != "documents.42" {
		t.Errorf("channels = %v", event.Channels)
	}

	if string(event.Payload) != `{"title":"renamed"}` {
		t.Errorf("payload = %s; it must be passed through verbatim", event.Payload)
	}

	// The bystander must have nothing waiting.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if _, _, err := bystander.Read(ctx); err == nil {
		t.Fatal("a connection that never subscribed received the event")
	}
}

func TestRevokeUnsubscribesAndTellsTheClient(t *testing.T) {
	auth := &fakeAuthorizer{allow: map[string]bool{"documents.42": true}}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{"type": "subscribe", "channels": []string{"documents.42"}})

	var reply protocol.Subscribed
	readJSON(t, conn, &reply)

	if n := srv.Revoke("documents.42"); n != 1 {
		t.Fatalf("revoked %d, want 1", n)
	}

	// TOLD, not silently dropped: a client that thinks it is subscribed waits
	// for events that are never coming.
	var notice protocol.Unsubscribed
	readJSON(t, conn, &notice)

	if notice.Type != "unsubscribed" || notice.Reason != "revoked" {
		t.Errorf("notice = %+v", notice)
	}

	envelope, _ := bus.Parse([]byte(`{"channels":["documents.42"],"event":{}}`), channel.Normalise)

	if n := srv.Deliver(envelope); n != 0 {
		t.Errorf("delivered to %d after a revoke, want 0", n)
	}
}

// ── The small protocol surface ──────────────────────────────────────────────

func TestAJsonPingIsAnsweredBecauseBrowsersCannotSendProtocolPings(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{"type": "ping"})

	var pong protocol.Pong
	readJSON(t, conn, &pong)

	if pong.Type != "pong" {
		t.Errorf("type = %q, want pong", pong.Type)
	}
}

func TestUnsubscribeConfirmsWhatWasRemoved(t *testing.T) {
	auth := &fakeAuthorizer{allow: map[string]bool{"a.1": true}}
	srv := New(testConfig(), auth, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{"type": "subscribe", "channels": []string{"a.1"}})

	var reply protocol.Subscribed
	readJSON(t, conn, &reply)

	writeJSON(t, conn, map[string]any{"type": "unsubscribe", "channels": []string{"a.1", "never.held"}})

	var notice protocol.Unsubscribed
	readJSON(t, conn, &notice)

	if len(notice.Channels) != 1 || notice.Channels[0] != "a.1" {
		t.Errorf("channels = %v; only what was actually removed", notice.Channels)
	}

	if notice.Reason != "requested" {
		t.Errorf("reason = %q", notice.Reason)
	}
}

func TestAMalformedMessageIsAnsweredNotIgnored(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":`)); err != nil {
		t.Fatal(err)
	}

	var failure protocol.Error
	readJSON(t, conn, &failure)

	if failure.Type != "error" {
		t.Errorf("type = %q, want error", failure.Type)
	}
}

// TestAChannelsFieldOfTheWrongTypeIsOneDecodeError.
//
// `{"channels": "documents.42"}` — a string, not a list. Handled in ONE place
// by the decoder, rather than being silently coerced into a one-element list by
// a hand-rolled parser.
func TestAChannelsFieldOfTheWrongTypeIsOneDecodeError(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	writeJSON(t, conn, map[string]any{"type": "subscribe", "channels": "documents.42"})

	var failure protocol.Error
	readJSON(t, conn, &failure)

	if failure.Type != "error" {
		t.Errorf("type = %q, want a single error", failure.Type)
	}
}

func TestABinaryFrameIsRefusedRatherThanIgnored(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := conn.Write(ctx, websocket.MessageBinary, []byte{0x00, 0x01}); err != nil {
		t.Fatal(err)
	}

	var failure protocol.Error
	readJSON(t, conn, &failure)

	if failure.Type != "error" {
		t.Error("a binary frame must be answered; silently dropping it leaves the client waiting")
	}
}

// ── Capacity and shutdown ───────────────────────────────────────────────────

// TestAtCapacityTheServerAnswers1013.
//
// The right code: a client that sees Try Again Later backs off and retries,
// where 1011 reads as a bug and 1008 as a refusal it should not repeat.
func TestAtCapacityTheServerAnswers1013(t *testing.T) {
	cfg := testConfig()
	cfg.MaxConnections = 1

	srv := New(cfg, &fakeAuthorizer{}, quietLogger())
	http1 := httptest.NewServer(srv.Handler())
	defer http1.Close()

	url := "ws" + strings.TrimPrefix(http1.URL, "http") + "/realtime"
	options := &websocket.DialOptions{
		HTTPHeader:   map[string][]string{"Origin": {"https://app.example.com"}},
		Subprotocols: []string{protocol.Subprotocol},
	}

	first, _, err := websocket.Dial(context.Background(), url, options)
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseNow()

	var connected protocol.Connected
	readJSON(t, first, &connected)

	second, _, err := websocket.Dial(context.Background(), url, options)
	if err != nil {
		t.Fatal(err)
	}
	defer second.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, readErr := second.Read(ctx)
	if readErr == nil {
		t.Fatal("the second connection should have been refused")
	}

	if status := websocket.CloseStatus(readErr); status != websocket.StatusTryAgainLater {
		t.Errorf("close status = %v, want 1013 Try Again Later", status)
	}
}

// TestShutdownClosesWith1001GoingAway.
//
// A client that sees a clean close reconnects immediately; one that sees a TCP
// reset waits out its backoff. On a deploy that is the difference between a
// blip and a minute of missed events.
func TestShutdownClosesWith1001GoingAway(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())

	_, conn := dial(t, srv, "https://app.example.com")

	var connected protocol.Connected
	readJSON(t, conn, &connected)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go srv.Shutdown(ctx)

	readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer readCancel()

	_, _, err := conn.Read(readCtx)
	if err == nil {
		t.Fatal("the connection should have been closed")
	}

	if status := websocket.CloseStatus(err); status != websocket.StatusGoingAway {
		t.Errorf("close status = %v, want 1001 Going Away", status)
	}
}

func TestAnAbsentOriginIsRefusedWhenRequired(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())
	http1 := httptest.NewServer(srv.Handler())
	defer http1.Close()

	_, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(http1.URL, "http")+"/realtime",
		&websocket.DialOptions{Subprotocols: []string{protocol.Subprotocol}})

	if err == nil {
		t.Fatal("a connection with no Origin must be refused when WEBSOCKET_REQUIRE_ORIGIN is true")
	}
}

func TestAWrongPathIs404(t *testing.T) {
	srv := New(testConfig(), &fakeAuthorizer{}, quietLogger())
	http1 := httptest.NewServer(srv.Handler())
	defer http1.Close()

	resp, err := http.Get(http1.URL + "/not-realtime")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
