package tsa

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestDefaultHTTPClientTimeout pins the package default client bound:
// a stalled or hostile TSA must fail the exchange instead of hanging
// it.
func TestDefaultHTTPClientTimeout(t *testing.T) {
	if defaultHTTPClient.Timeout != DefaultTimeout {
		t.Errorf("defaultHTTPClient.Timeout = %v, want DefaultTimeout %v",
			defaultHTTPClient.Timeout, DefaultTimeout)
	}
}

// TestClientSubmitStalledTSA: a raw listener that accepts the TCP
// connection and never writes a response (the black-hole TSA) must
// make submit fail with a timeout error instead of blocking forever.
// The package default client is temporarily swapped for a short
// timeout so the test runs in well under a second.
func TestClientSubmitStalledTSA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept the connection and hold it open, never responding.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	const shortTimeout = 300 * time.Millisecond
	orig := defaultHTTPClient
	defaultHTTPClient = &http.Client{Timeout: shortTimeout}
	t.Cleanup(func() { defaultHTTPClient = orig })

	c := NewClient("http://" + ln.Addr().String())
	// c.HTTPClient is left nil so submit falls back to the package
	// default (the short-timeout swap above).
	start := time.Now()
	_, err = c.submit(context.Background(), []byte{0x30, 0x03, 0x0A, 0x02, 0x01, 0x01})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("submit against a stalled TSA succeeded, want a timeout error")
	}
	if elapsed > 2*shortTimeout {
		t.Errorf("submit took %v, want < %v (2x the short timeout)", elapsed, 2*shortTimeout)
	}
}
