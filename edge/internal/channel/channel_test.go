package channel

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// vectors is the file the PHP suite reads too. See shared/channel-vectors.json.
//
// THIS IS THE ANTI-DRIFT MECHANISM, and it is the reason a second
// implementation of the channel rules is tolerable at all. A rule changed on
// one side and not the other fails here or in the PHP suite — not in
// production, where the stricter implementation silently decides what is
// reachable.
const vectorPath = "../../../shared/channel-vectors.json"

type vectorFile struct {
	Valid      []string          `json:"valid"`
	Normalises map[string]string `json:"normalises"`
	Invalid    []string          `json:"invalid"`
}

func load(t *testing.T) vectorFile {
	t.Helper()

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("the shared vectors are missing (%v). They are not optional: without them the Go and PHP channel rules drift silently.", err)
	}

	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("the shared vectors are not valid JSON: %v", err)
	}

	if len(file.Valid) == 0 || len(file.Invalid) == 0 {
		t.Fatal("the shared vectors are empty, so this test proves nothing")
	}

	return file
}

func TestSharedVectorsValid(t *testing.T) {
	for _, name := range load(t).Valid {
		if got := Normalise(name); got != name {
			t.Errorf("Normalise(%q) = %q; the shared vectors say it is valid and must come back unchanged", name, got)
		}

		if !Valid(name) {
			t.Errorf("Valid(%q) = false; the shared vectors say it is valid", name)
		}
	}
}

func TestSharedVectorsNormalise(t *testing.T) {
	for raw, want := range load(t).Normalises {
		if got := Normalise(raw); got != want {
			t.Errorf("Normalise(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestSharedVectorsInvalid(t *testing.T) {
	for _, name := range load(t).Invalid {
		if got := Normalise(name); got != "" {
			t.Errorf("Normalise(%q) = %q; the shared vectors say it must be REFUSED", name, got)
		}
	}
}

// TestEveryControlByteIsRefused covers what JSON cannot carry.
//
// NUL is the one that matters: PHP's default trim() strips it, so
// "documents.42\x00" was silently normalised into the perfectly valid channel
// "documents.42" rather than refused. Go's strings.Trim with an explicit cutset
// does not, and this asserts it stays that way on both sides.
func TestEveryControlByteIsRefused(t *testing.T) {
	for b := 0; b <= 0x1F; b++ {
		name := "documents." + string(rune(b)) + "42"

		if got := Normalise(name); got != "" {
			t.Errorf("byte 0x%02X was accepted as %q", b, got)
		}
	}

	if got := Normalise("documents.\x7f42"); got != "" {
		t.Errorf("DEL was accepted as %q", got)
	}

	// And a trailing NUL must NOT be trimmed away into a valid name.
	if got := Normalise("documents.42\x00"); got != "" {
		t.Errorf("a trailing NUL was trimmed into %q instead of being refused", got)
	}
}

func TestLengthLimit(t *testing.T) {
	atLimit := strings.Repeat("a", MaxLength)
	if Normalise(atLimit) != atLimit {
		t.Errorf("a name of exactly %d bytes must be accepted", MaxLength)
	}

	if got := Normalise(strings.Repeat("a", MaxLength+1)); got != "" {
		t.Errorf("a name of %d bytes was accepted as %q", MaxLength+1, got)
	}

	// The limit applies AFTER trimming, so whitespace must not make a usable
	// name unusable.
	padded := "  " + atLimit + "  "
	if Normalise(padded) != atLimit {
		t.Error("the length limit must be applied after trimming, not before")
	}
}

func TestPrefix(t *testing.T) {
	cases := map[string]string{
		"documents.42":            "documents",
		"collections.7.documents": "collections",
		"events":                  "events",
	}

	for name, want := range cases {
		if got := Prefix(name); got != want {
			t.Errorf("Prefix(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestNormaliseAllNeverReturnsNil is a Go-specific correctness test.
//
// A nil slice marshals to JSON `null`, and a browser doing `denied.length` on
// null throws. The PHP side cannot have this bug; Go can, so it is pinned.
func TestNormaliseAllNeverReturnsNil(t *testing.T) {
	accepted, rejected := NormaliseAll(nil, 10)

	if accepted == nil || rejected == nil {
		t.Fatal("both slices must be non-nil: a nil slice marshals to JSON null, and null.length throws in a browser")
	}

	encoded, err := json.Marshal(map[string]any{"granted": accepted, "denied": rejected})
	if err != nil {
		t.Fatal(err)
	}

	if string(encoded) != `{"denied":[],"granted":[]}` {
		t.Errorf("empty lists must encode as [], got %s", encoded)
	}
}

func TestNormaliseAllDeduplicates(t *testing.T) {
	accepted, rejected := NormaliseAll([]string{"a.1", "a.1", " a.1 ", "a.2"}, 10)

	if len(accepted) != 2 {
		t.Errorf("want 2 distinct channels, got %v", accepted)
	}

	if len(rejected) != 0 {
		t.Errorf("a duplicate is not a rejection, got %v", rejected)
	}
}

// TestNormaliseAllEnforcesTheCap stops a client choosing how much work the
// edge does. Everything past the cap is rejected locally, so no NATS round
// trip is spent on it.
func TestNormaliseAllEnforcesTheCap(t *testing.T) {
	var requested []string
	for i := 0; i < 100; i++ {
		requested = append(requested, fmt.Sprintf("documents.%d", i))
	}

	accepted, rejected := NormaliseAll(requested, 8)

	if len(accepted) != 8 {
		t.Errorf("want 8 accepted, got %d", len(accepted))
	}

	if len(rejected) != 92 {
		t.Errorf("want 92 rejected, got %d", len(rejected))
	}
}

func TestInvalidNamesAreRejectedNotSilentlyDropped(t *testing.T) {
	accepted, rejected := NormaliseAll([]string{"good.1", "bad name", "documents.*", "good.2"}, 10)

	if len(accepted) != 2 {
		t.Errorf("want the two good names, got %v", accepted)
	}

	// Reported, not dropped: a client that asked for four channels and was
	// told about two has no way to know what happened to the others.
	if len(rejected) != 2 {
		t.Errorf("want the two bad names reported, got %v", rejected)
	}
}
