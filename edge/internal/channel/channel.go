// Package channel validates channel names, with the same rules as the PHP side.
//
// THIS IS A SECOND IMPLEMENTATION OF ONE RULE SET, AND THAT IS A LIABILITY
// -----------------------------------------------------------------------
// Plugins\WebSocket\Domain\Channel is the original. Two implementations of a
// security rule drift, and the drift is silent: the stricter one refuses
// something the other allows, and whichever side a deployment happens to run
// decides what is reachable.
//
// It is duplicated anyway, deliberately, because the alternative is worse. The
// edge has to reject a malformed name BEFORE spending a NATS round trip asking
// PHP about it — otherwise a client can make the edge flood the authorizer with
// garbage, and an unauthenticated client choosing how much work the application
// does is a denial-of-service primitive.
//
// So the rules are kept identical and the SHARED TEST VECTORS in
// testdata/channels.json are the thing that keeps them that way: the PHP suite
// and the Go suite read the same file, so a change to either side that is not
// made to both fails on one of them.
//
// AUTHORIZATION IS NOT HERE. It stays in PHP, reached over NATS, because that
// is the decision that must have exactly one implementation.
package channel

import "strings"

// MaxLength mirrors Channel::MAX_LENGTH.
const MaxLength = 128

// Valid reports whether name is usable as a channel.
//
// No wildcards, by the same reasoning as the PHP side: a pattern inverts where
// the decision is made, because the authorizer gets asked about a thing that
// does not exist and has no owner, then has to answer for everything that might
// ever match it — including objects created after the grant.
func Valid(name string) bool {
	return Normalise(name) != ""
}

// Normalise trims and returns the canonical name, or "" when unusable.
//
// The trim set is exactly " \t\n\r", NOT Go's unicode.IsSpace. That is a
// deliberate match for PHP's `trim($raw, " \t\n\r")`, which is itself narrower
// than PHP's default — the default also strips NUL and the vertical tab, so
// "documents.42\x00" came back as a VALID name instead of being refused. A
// control byte in a channel name means a broken client or a probe, and either
// way it should not be quietly normalised into something acceptable.
//
// strings.TrimSpace would reintroduce the same bug from the other direction by
// also stripping \v and \f.
func Normalise(raw string) string {
	name := strings.Trim(raw, " \t\n\r")

	if name == "" || len(name) > MaxLength {
		return ""
	}

	// Refused: whitespace of any kind, control bytes, and the two wildcard
	// characters. Checked by byte rather than by rune — every permitted
	// character is ASCII, so a multi-byte sequence cannot produce one, and a
	// byte-wise check cannot be fooled by an overlong encoding.
	for i := 0; i < len(name); i++ {
		c := name[i]

		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			continue
		case c == '.' || c == '-' || c == '_' || c == ':':
			continue
		default:
			return ""
		}
	}

	// A leading or trailing separator, or a doubled one, means an empty token —
	// which would make "documents." and "documents" different channels that
	// look the same in a log.
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return ""
	}

	return name
}

// Prefix is the first dotted token, which is what an authorizer switches on.
func Prefix(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}

	return name
}

// NormaliseAll filters a client's list down to usable, de-duplicated names.
//
// Returns the accepted names and the rejected RAW strings separately, so the
// caller can refuse the bad ones without asking PHP about them and without
// telling the client why — the reason goes to the log, never to the socket.
func NormaliseAll(raw []string, limit int) (accepted []string, rejected []string) {
	// Both initialised, never nil. A nil slice marshals to JSON `null`, and a
	// client doing `denied.length` on null throws — so `granted` and `denied`
	// must always be arrays even when empty. This is the Go-specific version of
	// the same promise the PHP side makes.
	accepted = []string{}
	rejected = []string{}
	seen := make(map[string]struct{}, len(raw))

	for _, candidate := range raw {
		if limit > 0 && len(accepted) >= limit {
			rejected = append(rejected, candidate)
			continue
		}

		name := Normalise(candidate)
		if name == "" {
			rejected = append(rejected, candidate)
			continue
		}

		if _, duplicate := seen[name]; duplicate {
			continue
		}

		seen[name] = struct{}{}
		accepted = append(accepted, name)
	}

	return accepted, rejected
}
