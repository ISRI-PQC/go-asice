package tsa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/isri-pqc/go-asice/testutil"
	tcrypto "github.com/isri-pqc/go-asice/tsa/crypto"
)

// testTSA is an in-process RFC 3161 test TSA. It verifies the request
// imprint against the SHA-256 of signData, echoes the request nonce,
// and issues a testutil TST (ECDSA-SHA256) over signData.
type testTSA struct {
	p        *testutil.PKI
	signData []byte
	failNext int  // number of requests that receive HTTP 500
	status   int  // pkiStatus to return (0 = granted)
	corrupt  bool // flip a byte in the token signature before replying
}

func (s *testTSA) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if s.failNext > 0 {
			s.failNext--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("Content-Type") != ContentTypeQuery {
			http.Error(w, "unexpected content type", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := ParseTimeStampReq(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(s.signData)
		if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(OidSHA256) {
			http.Error(w, "unexpected imprint algorithm", http.StatusBadRequest)
			return
		}
		if !bytes.Equal(req.MessageImprint.HashedMessage, sum[:]) {
			http.Error(w, "imprint does not match the server data", http.StatusBadRequest)
			return
		}

		status := s.status
		var token []byte
		if status == 0 {
			token, err = s.p.TimeStampToken(s.signData, testutil.TSTOptions{
				GenTime: time.Now().UTC(),
				Nonce:   req.Nonce,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if s.corrupt {
			token[len(token)-2] ^= 0xFF
		}
		statusDER, err := asn1.Marshal(struct {
			Status int
		}{Status: status})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ContentTypeReply)
		if _, err := w.Write(append(statusDER, token...)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}
}

// newTestPKI returns a fresh test PKI valid at the current time.
func newTestPKI(t *testing.T) *testutil.PKI {
	t.Helper()
	p, err := testutil.NewPKI(testutil.Options{Now: time.Now()})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	return p
}

// TestClientE2E is the acceptance path: client -> test TSA ->
// structurally and cryptographically valid token -> full Validator
// validation against the test PKI roots.
// testClient returns a Client with the standard crypto modules wired
// (the test default).
func testClient(url string) *Client {
	c := NewClient(url)
	c.DigestModule = tcrypto.NewStdDigestModule()
	c.SignatureVerifierModule = tcrypto.NewStdSignatureVerifierModule()
	return c
}

func TestClientE2E(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("e2e acceptance data: canonicalized ds:SignatureValue bytes")

	tsa := &testTSA{p: p, signData: data}
	server := httptest.NewServer(tsa.handler(t))
	defer server.Close()

	c := testClient(server.URL)
	c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}

	tokenDER, gen, err := c.Create(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("Client.Create: %v", err)
	}
	if now := time.Now(); gen.Before(now.Add(-5*time.Second)) || gen.After(now.Add(5*time.Second)) {
		t.Errorf("genTime %s is more than 5s away from now %s", gen.UTC(), now.UTC())
	}

	// The token must be a TST over the exact data.
	parsed, err := Parse(tokenDER)
	if err != nil {
		t.Fatalf("Parse returned token: %v", err)
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(parsed.Content.EncapContentInfo.TSTInfo.MessageImprint.HashedMessage, sum[:]) {
		t.Errorf("token imprint != SHA-256(data)")
	}

	// Full validation: trust the token against the test PKI.
	v := withStdModules(&Validator{
		Roots:      []*x509.Certificate{p.Root.Certificate},
		TSTSigners: []*x509.Certificate{p.TSA.Certificate},
	})
	gotGen, err := v.Check(tokenDER, data, CheckOptions{FreshnessCheck: true, Now: time.Now()})
	if err != nil {
		t.Fatalf("Validator.Check rejected the e2e token: %v", err)
	}
	if !gotGen.Equal(gen) {
		t.Errorf("Check genTime %s != Create genTime %s", gotGen.UTC(), gen.UTC())
	}

	// A caller-provided nonce must be echoed: validate with it.
	nonce := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	tokenDER2, _, err := c.Create(context.Background(), data, nonce)
	if err != nil {
		t.Fatalf("Client.Create with nonce: %v", err)
	}
	if _, err := v.Check(tokenDER2, data, CheckOptions{Nonce: nonce}); err != nil {
		t.Fatalf("Validator.Check with the supplied nonce: %v", err)
	}
	// A different nonce must not validate.
	wrong := new(big.Int).Add(nonce, big.NewInt(1))
	if _, err := v.Check(tokenDER2, data, CheckOptions{Nonce: wrong}); err == nil {
		t.Fatalf("Validator.Check accepted the token with the wrong nonce")
	}
}

// TestClientE2ERetry: 5xx responses are retried c.Retry times.
func TestClientE2ERetry(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("retry data")

	t.Run("within budget succeeds", func(t *testing.T) {
		tsa := &testTSA{p: p, signData: data, failNext: 2}
		server := httptest.NewServer(tsa.handler(t))
		defer server.Close()

		c := testClient(server.URL)
		c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
		c.Retry = 3
		if _, _, err := c.Create(context.Background(), data, nil); err != nil {
			t.Fatalf("Client.Create after 2 failed attempts: %v", err)
		}
	})

	t.Run("over budget fails", func(t *testing.T) {
		tsa := &testTSA{p: p, signData: data, failNext: 5}
		server := httptest.NewServer(tsa.handler(t))
		defer server.Close()

		c := testClient(server.URL)
		c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
		c.Retry = 1
		if _, _, err := c.Create(context.Background(), data, nil); err == nil {
			t.Fatalf("Client.Create succeeded although every response was 500")
		}
	})
}

// TestClientE2ERejected: a non-granted pkiStatus is surfaced.
func TestClientE2ERejected(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("rejected data")
	tsa := &testTSA{p: p, signData: data, status: 2} // badReq
	server := httptest.NewServer(tsa.handler(t))
	defer server.Close()

	c := testClient(server.URL)
	c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	if _, _, err := c.Create(context.Background(), data, nil); err == nil {
		t.Fatalf("Client.Create accepted a pkiStatus 2 response")
	}
}

// TestClientE2ETamperedToken: the TSA returns a token whose
// signature bytes are corrupted; the client must reject it.
func TestClientE2ETamperedToken(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("tamper data")

	// Capture the granted response and corrupt the signature bytes.
	good := testTSA{p: p, signData: data}
	goodServer := httptest.NewServer(good.handler(t))
	c := testClient(goodServer.URL)
	c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	if _, _, err := c.Create(context.Background(), data, nil); err != nil {
		t.Fatalf("baseline Client.Create: %v", err)
	}
	goodServer.Close()

	bad := testTSA{p: p, signData: data, corrupt: true}
	badServer := httptest.NewServer(bad.handler(t))
	defer badServer.Close()

	c2 := testClient(badServer.URL)
	c2.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	if _, _, err := c2.Create(context.Background(), data, nil); err == nil {
		t.Fatalf("Client.Create accepted a token with corrupted signature bytes")
	}
}

// TestClientPolicy: when the client requires a policy OID, tokens with
// a different TSTInfo policy are rejected; the default (empty) accepts
// any policy.
func TestClientPolicy(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("policy data")
	tsa := &testTSA{p: p, signData: data}
	server := httptest.NewServer(tsa.handler(t))
	defer server.Close()

	// testutil's default TST policy is 0.4.0.2023.1.1.
	wantPolicy := asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}

	c := testClient(server.URL)
	c.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	if _, _, err := c.Create(context.Background(), data, nil); err != nil {
		t.Fatalf("Client.Create with no policy requirement: %v", err)
	}

	c2 := testClient(server.URL)
	c2.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	c2.Policy = wantPolicy
	if _, _, err := c2.Create(context.Background(), data, nil); err != nil {
		t.Fatalf("Client.Create with the matching policy: %v", err)
	}

	c3 := testClient(server.URL)
	c3.TSTSigners = []*x509.Certificate{p.TSA.Certificate}
	c3.Policy = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 2}
	if _, _, err := c3.Create(context.Background(), data, nil); err == nil {
		t.Fatalf("Client.Create accepted a token with the wrong policy")
	}
}
