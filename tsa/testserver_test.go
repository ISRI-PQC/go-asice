// Tests for the exported in-process test TSA server (tsa/testserver.go).
package tsa

import (
	"context"
	"crypto/x509"
	"testing"
	"time"
)

// TestTestServerE2E is the helper milestone: request over HTTP to the
// in-process TSA -> structurally and cryptographically valid token ->
// full Validator.Check against the testutil PKI roots. (Same shape as
// TestClientE2E, which feeds the private testTSA; this pins the
// EXPORTED helper the acceptance CLI tests use.)
func TestTestServerE2E(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("test server e2e data")
	gen := time.Now().UTC().Truncate(time.Second)

	srv, err := NewTestServer(TestServerOptions{
		Certificate: p.TSA.Certificate,
		PrivateKey:  p.TSA.PrivateKey,
		GenTime:     gen,
	})
	if err != nil {
		t.Fatalf("NewTestServer: %v", err)
	}
	defer srv.Close()

	c := testClient(srv.URL)
	c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	token, gotGen, err := c.Create(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("Client.Create: %v", err)
	}
	if !gotGen.Equal(gen) {
		t.Errorf("genTime %s != configured GenTime %s", gotGen.UTC(), gen.UTC())
	}

	v := withStdModules(&Validator{
		Roots:      []*x509.Certificate{p.Root.Certificate},
		TSTSigners: []*x509.Certificate{p.TSA.Certificate},
	})
	if _, err := v.Check(token, data, CheckOptions{FreshnessCheck: true, Now: time.Now()}); err != nil {
		t.Fatalf("Validator.Check rejected the helper token: %v", err)
	}
}

// TestTestServerValidation pins the option contract errors.
func TestTestServerValidation(t *testing.T) {
	p := newTestPKI(t)
	cases := []struct {
		name string
		opts TestServerOptions
	}{
		{"no cert", TestServerOptions{PrivateKey: p.TSA.PrivateKey, GenTime: time.Now()}},
		{"no key", TestServerOptions{Certificate: p.TSA.Certificate, GenTime: time.Now()}},
		{"zero gen", TestServerOptions{Certificate: p.TSA.Certificate, PrivateKey: p.TSA.PrivateKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewTestServer(tc.opts); err == nil {
				t.Fatalf("NewTestServer succeeded, want error")
			}
		})
	}
}
