package resolve

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A missing PTR record is the normal case on a LAN, not an error: Lookup is
// best-effort and must degrade to an empty hostname.
func TestLookupReturnsEmptyOnFailure(t *testing.T) {
	if got := Lookup(context.Background(), "not-an-ip-address"); got != "" {
		t.Errorf("Lookup(garbage) = %q, want empty", got)
	}
}

// An address in the documentation range has no PTR record anywhere.
func TestLookupReturnsEmptyForUnresolvableAddress(t *testing.T) {
	if got := Lookup(context.Background(), "192.0.2.1"); got != "" {
		t.Errorf("Lookup(192.0.2.1) = %q, want empty", got)
	}
}

// A cancelled context must not make Lookup hang or fail hard. It deliberately
// does NOT assert an empty result: on Windows the system resolver can satisfy a
// lookup from cache before it observes the cancellation, so a name coming back
// is legitimate. The contract is "returns promptly, never panics, well-formed".
func TestLookupHandlesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	got := Lookup(ctx, "8.8.8.8")
	elapsed := time.Since(start)

	if elapsed >= 2*time.Second {
		t.Errorf("Lookup took %v on a cancelled context, want it to give up promptly", elapsed)
	}
	if strings.HasSuffix(got, ".") {
		t.Errorf("Lookup = %q, want any result to have its trailing dot stripped", got)
	}
}

// When a name does come back it must be usable as-is, with the trailing dot of
// the DNS wire format removed.
func TestLookupStripsTrailingDot(t *testing.T) {
	got := Lookup(context.Background(), "127.0.0.1")
	if got == "" {
		t.Skip("no PTR record for 127.0.0.1 in this environment")
	}
	if strings.HasSuffix(got, ".") {
		t.Errorf("Lookup = %q, want the trailing dot stripped", got)
	}
}
