// Package config reads the same WEBSOCKET_* variables the PHP server reads.
//
// THE SAME NAMES, DELIBERATELY. An operator who swaps the PHP server for this
// edge should not have to re-learn or re-declare their configuration, and a
// second set of names would mean two places to change a limit — with the usual
// result that one of them is changed.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved, validated settings.
type Config struct {
	Listen  string
	Path    string
	Origins []string

	// RequireOrigin false accepts a connection with NO Origin header.
	// Correct for a native client, which must then authenticate by token, and
	// wrong for a browser-only deployment, where it removes the hijacking
	// defence for any client that simply omits the header.
	RequireOrigin bool

	NatsURL     string
	NatsUser    string
	NatsPass    string
	NatsToken   string
	BusSubject  string
	AuthSubject string

	MaxConnections  int
	MaxChannels     int
	MaxMessageBytes int64
	SendBuffer      int

	IdleTimeout      time.Duration
	WriteTimeout     time.Duration
	AuthorizeTimeout time.Duration

	HealthListen string
}

// Load reads the environment and refuses anything unusable.
//
// It FAILS rather than defaulting on the one setting that has no safe default.
// See the Origins check: a permissive default would mean every deployment that
// did not think about Cross-Site WebSocket Hijacking shipped it, invisibly,
// because the legitimate client works either way.
func Load() (Config, error) {
	c := Config{
		Listen:           text("WEBSOCKET_LISTEN", "127.0.0.1:9503"),
		Path:             path(text("WEBSOCKET_PATH", "/realtime")),
		Origins:          origins(os.Getenv("WEBSOCKET_ORIGINS")),
		RequireOrigin:    boolean("WEBSOCKET_REQUIRE_ORIGIN", true),
		NatsURL:          text("NATS_URL", "nats://127.0.0.1:4222"),
		NatsUser:         os.Getenv("NATS_USER"),
		NatsPass:         os.Getenv("NATS_PASS"),
		NatsToken:        os.Getenv("NATS_TOKEN"),
		BusSubject:       text("WEBSOCKET_BUS_CHANNEL", "hkm.rt.events"),
		AuthSubject:      text("WEBSOCKET_AUTH_SUBJECT", "hkm.rt.authorize"),
		MaxConnections:   number("WEBSOCKET_MAX_CONNECTIONS", 10000),
		MaxChannels:      number("WEBSOCKET_MAX_CHANNELS", 64),
		MaxMessageBytes:  int64(number("WEBSOCKET_MAX_MESSAGE_BYTES", 8388608)),
		SendBuffer:       number("WEBSOCKET_SEND_BUFFER", 64),
		IdleTimeout:      seconds("WEBSOCKET_IDLE_TIMEOUT", 120),
		WriteTimeout:     seconds("WEBSOCKET_WRITE_TIMEOUT", 10),
		AuthorizeTimeout: seconds("WEBSOCKET_AUTHORIZE_TIMEOUT", 2),
		HealthListen:     text("WEBSOCKET_HEALTH_LISTEN", "127.0.0.1:9504"),
	}

	if len(c.Origins) == 0 {
		return c, errors.New(
			"WEBSOCKET_ORIGINS is empty, so every connection would be refused and this server has " +
				"nothing to do.\n\n" +
				"A WebSocket handshake is NOT subject to the same-origin policy: the browser lets any " +
				"page open a socket to any host, performs no CORS preflight, and attaches the target " +
				"site's cookies. So a page on any site can open a socket that arrives authenticated as " +
				"your logged-in visitor, and the Origin header is the only place that can be stopped.\n\n" +
				"Set it to your exact origins, comma separated:\n" +
				"  WEBSOCKET_ORIGINS=https://app.example.com,https://admin.example.com",
		)
	}

	for _, origin := range c.Origins {
		if strings.Contains(origin, "*") {
			return c, fmt.Errorf(
				"WEBSOCKET_ORIGINS contains a wildcard (%q), which is not supported. Matching is exact "+
					"on the whole origin, because a suffix or wildcard test accepts "+
					"https://app.example.com.attacker.net as readily as the real host", origin)
		}
	}

	if c.MaxMessageBytes <= 0 {
		return c, errors.New("WEBSOCKET_MAX_MESSAGE_BYTES must be positive")
	}

	return c, nil
}

// AllowsOrigin matches EXACTLY and case-insensitively on the whole origin.
//
// Never a suffix test. `strings.HasSuffix(origin, "example.com")` accepts every
// one of these, and each is a different site under somebody else's control:
//
//	https://evil-app.example.com      https://app.example.com.attacker.net
//	https://app.example.com@evil.test http://app.example.com
//
// The last one matters as much as the others: the scheme is part of the origin,
// so an http:// page must not match an https:// allowlist entry.
func (c Config) AllowsOrigin(origin string) bool {
	if origin == "" {
		// No Origin header at all. A non-browser client sends none, and it has
		// no victim's cookies to borrow — which is the entire reason the header
		// matters. Permitted only when the operator said so.
		return !c.RequireOrigin
	}

	candidate := strings.ToLower(strings.TrimSpace(origin))

	for _, allowed := range c.Origins {
		if strings.ToLower(allowed) == candidate {
			return true
		}
	}

	return false
}

func origins(raw string) []string {
	out := []string{}

	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

func path(raw string) string {
	if !strings.HasPrefix(raw, "/") {
		return "/" + raw
	}

	return raw
}

func text(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}

	return fallback
}

func boolean(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))

	if v == "" {
		return fallback
	}

	// Anything unrecognised is false, INCLUDING a typo — matching the PHP
	// side. For WEBSOCKET_REQUIRE_ORIGIN that means a typo turns the defence
	// off, which is why it is reported at startup rather than assumed.
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func number(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}

	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}

	return n
}

func seconds(key string, fallback int) time.Duration {
	return time.Duration(number(key, fallback)) * time.Second
}
