package ports

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestOpenDetectsListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Grab a second port, then close it so it is (almost certainly) refused.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	got, ok := Open(context.Background(), "127.0.0.1", []int{openPort, closedPort}, time.Second)
	if !ok {
		t.Fatal("Open reported incomplete on an uncancelled context")
	}
	if len(got) != 1 || got[0] != openPort {
		t.Fatalf("Open = %v, want [%d]", got, openPort)
	}
}

func TestOpenSortsResults(t *testing.T) {
	var wantPorts []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		wantPorts = append(wantPorts, ln.Addr().(*net.TCPAddr).Port)
	}

	got, ok := Open(context.Background(), "127.0.0.1", wantPorts, time.Second)
	if !ok {
		t.Fatal("Open reported incomplete on an uncancelled context")
	}
	if len(got) != 3 {
		t.Fatalf("Open returned %d ports, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("results not sorted ascending: %v", got)
		}
	}
}

// A cancelled context makes every dial fail instantly, which is
// indistinguishable from a closed port. Open must report that as incomplete
// rather than as an empty (clean) result.
func TestOpenReportsIncompleteOnCancelledContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, ok := Open(ctx, "127.0.0.1", []int{openPort}, time.Second)
	if ok {
		t.Errorf("Open reported complete on a cancelled context (got %v)", got)
	}
	if got != nil {
		t.Errorf("Open = %v, want nil on a cancelled context", got)
	}
}
