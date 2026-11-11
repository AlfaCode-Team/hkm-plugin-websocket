package config

import "testing"

// base is an allowlist shaped like a real one.
func base() Config {
	return Config{
		Origins:       []string{"https://app.example.com", "https://admin.example.com"},
		RequireOrigin: true,
	}
}

// TestTheHijackingVectorsAreAllRefused is the most important test in the edge.
//
// A WebSocket handshake is not subject to the same-origin policy: the browser
// lets any page open a socket to any host, performs no CORS preflight, and
// ATTACHES THE TARGET SITE'S COOKIES. So `new WebSocket('wss://app.example.com/
// realtime')` from any page on the internet arrives authenticated as the
// logged-in victim, and Origin is the only place it can be stopped.
//
// Every string below is what a suffix or wildcard test lets through, and each
// is a different site under somebody else's control. The last one is the one
// people forget: the SCHEME is part of an origin, so an http:// page must not
// match an https:// allowlist entry.
func TestTheHijackingVectorsAreAllRefused(t *testing.T) {
	cfg := base()

	refused := []string{
		"https://evil-app.example.com",         // a sibling subdomain
		"https://app.example.com.attacker.net", // the allowlist entry as a PREFIX of another domain
		"https://attacker.net/app.example.com", // in a path
		"https://app.example.com@evil.test",    // userinfo trick
		"http://app.example.com",               // wrong scheme
		"https://app.example.com:8443",         // a different port is a different origin
		"https://App.Example.Com.evil.test",
		"https://xn--app-example.com",
		"null",
		"file://",
		"https://app.example.com ",      // trailing space is trimmed, then matched — see below
		" https://app.example.com.evil", // leading space must not help
	}

	for _, origin := range refused {
		// The one exception in the list: a trailing space IS trimmed and then
		// matches, which is correct — the header value is whitespace-padded by
		// some proxies and the origin itself cannot contain a space.
		if origin == "https://app.example.com " {
			if !cfg.AllowsOrigin(origin) {
				t.Errorf("AllowsOrigin(%q) = false; a padded header should trim and match", origin)
			}

			continue
		}

		if cfg.AllowsOrigin(origin) {
			t.Errorf("AllowsOrigin(%q) = true; this is a DIFFERENT site and must be refused", origin)
		}
	}
}

func TestAllowedOriginsMatchExactlyAndCaseInsensitively(t *testing.T) {
	cfg := base()

	for _, origin := range []string{
		"https://app.example.com",
		"HTTPS://APP.EXAMPLE.COM",
		"https://App.Example.com",
		"https://admin.example.com",
	} {
		if !cfg.AllowsOrigin(origin) {
			t.Errorf("AllowsOrigin(%q) = false; it is on the allowlist", origin)
		}
	}
}

// TestAnAbsentOriginFollowsRequireOrigin.
//
// A non-browser client sends no Origin at all, and it has no victim's cookies
// to borrow — which is the entire reason the header matters. So permitting it
// is correct for a mobile app and wrong for a browser-only deployment, where it
// removes the defence for any client that simply omits the header.
func TestAnAbsentOriginFollowsRequireOrigin(t *testing.T) {
	strict := base()
	if strict.AllowsOrigin("") {
		t.Error("with RequireOrigin true, a missing Origin must be refused")
	}

	relaxed := base()
	relaxed.RequireOrigin = false

	if !relaxed.AllowsOrigin("") {
		t.Error("with RequireOrigin false, a missing Origin must be accepted")
	}

	// Relaxing the MISSING case must not relax the WRONG case.
	if relaxed.AllowsOrigin("https://attacker.test") {
		t.Error("RequireOrigin=false must not accept a wrong Origin, only an absent one")
	}
}

// TestAnEmptyAllowlistRefusesEverything — the state Load() refuses to start in.
func TestAnEmptyAllowlistRefusesEverything(t *testing.T) {
	cfg := Config{Origins: nil, RequireOrigin: true}

	for _, origin := range []string{"", "https://app.example.com", "https://anything"} {
		if cfg.AllowsOrigin(origin) {
			t.Errorf("an empty allowlist must refuse %q", origin)
		}
	}
}

func TestLoadRefusesAnEmptyAllowlist(t *testing.T) {
	t.Setenv("WEBSOCKET_ORIGINS", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load must refuse to start with no origins: a server that accepts connections and " +
			"refuses every one of them is indistinguishable from an application where nothing happens")
	}
}

func TestLoadRefusesAWildcardOrigin(t *testing.T) {
	t.Setenv("WEBSOCKET_ORIGINS", "https://*.example.com")

	_, err := Load()
	if err == nil {
		t.Fatal("a wildcard origin must be refused: it accepts app.example.com.attacker.net too")
	}
}

func TestLoadDefaultsAndPathNormalisation(t *testing.T) {
	t.Setenv("WEBSOCKET_ORIGINS", "https://app.example.com")
	t.Setenv("WEBSOCKET_PATH", "realtime")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Path != "/realtime" {
		t.Errorf("Path = %q; a missing leading slash must be added, or nothing matches", cfg.Path)
	}

	if cfg.MaxChannels != 64 || cfg.MaxConnections != 10000 {
		t.Errorf("the defaults must match the PHP server's: got channels=%d connections=%d",
			cfg.MaxChannels, cfg.MaxConnections)
	}
}

// TestATypoInRequireOriginIsFalse matches the PHP side exactly.
//
// Worth pinning because the consequence is asymmetric: a typo turns the
// hijacking defence OFF rather than on, which is why the server logs a warning
// about it at startup rather than assuming anybody noticed.
func TestATypoInRequireOriginIsFalse(t *testing.T) {
	t.Setenv("WEBSOCKET_ORIGINS", "https://app.example.com")
	t.Setenv("WEBSOCKET_REQUIRE_ORIGIN", "ture")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.RequireOrigin {
		t.Error("an unrecognised value must be false, matching the PHP helper")
	}
}

func TestANegativeOrNonNumericLimitFallsBackToTheDefault(t *testing.T) {
	t.Setenv("WEBSOCKET_ORIGINS", "https://app.example.com")
	t.Setenv("WEBSOCKET_MAX_CHANNELS", "-5")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Not honoured: a negative cap would disable the limit, and that is far
	// more likely to be a typo than an intention.
	if cfg.MaxChannels != 64 {
		t.Errorf("MaxChannels = %d, want the 64 default", cfg.MaxChannels)
	}
}
