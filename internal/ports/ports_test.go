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

	got := Open(context.Background(), "127.0.0.1", []int{openPort, closedPort}, time.Second)

	if len(got) != 1 || got[0] != openPort {
		t.Fatalf("Open = %v, want [%d]", got, openPort)
	}
}

func TestOpenSortsResults(t *testing.T) {
	var listeners []net.Listener
	var wantPorts []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		listeners = append(listeners, ln)
		wantPorts = append(wantPorts, ln.Addr().(*net.TCPAddr).Port)
	}

	got := Open(context.Background(), "127.0.0.1", wantPorts, time.Second)
	if len(got) != 3 {
		t.Fatalf("Open returned %d ports, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("results not sorted ascending: %v", got)
		}
	}
}
