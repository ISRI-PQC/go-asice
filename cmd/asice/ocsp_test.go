// Unit tests of the ocsp fetch CLI flow over an httptest responder.
package main

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/isri-pqc/go-asice/testutil"
)

var cliFetchT = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// newFetchResponder starts an httptest responder that answers with a
// fresh "good" response for the PKI signer, after checking the
// request is a well-formed single-request OCSPRequest (RFC 6960 2.2).
func newFetchResponder(t *testing.T, p *testutil.PKI) *httptest.Server {
	t.Helper()
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "content type "+r.Header.Get("Content-Type"), http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req struct {
			RequestList []struct {
				ReqCert struct {
					HashAlgorithm  pkix.AlgorithmIdentifier
					IssuerNameHash []byte
					IssuerKeyHash  []byte
					SerialNumber   *big.Int
				}
			}
		}
		if _, err := asn1.Unmarshal(body, &req); err != nil || len(req.RequestList) != 1 {
			http.Error(w, "not a single-request OCSPRequest", http.StatusBadRequest)
			return
		}
		if !req.RequestList[0].ReqCert.HashAlgorithm.Algorithm.Equal(sha1OID) {
			http.Error(w, "hash algorithm not SHA-1", http.StatusBadRequest)
			return
		}
		respDER, err := p.OCSPResponse(cliFetchT)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respDER)
	}))
}

// proxyFetch is the actual responder body (the server above cannot
// know the PKI before it is built; the real tests build the server
// with a pointer indirection as here).
func proxyFetch(w http.ResponseWriter, r *http.Request, p *testutil.PKI) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		http.Error(w, "bad content type", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		RequestList []struct {
			ReqCert struct {
				HashAlgorithm  pkix.AlgorithmIdentifier
				IssuerNameHash []byte
				IssuerKeyHash  []byte
				SerialNumber   *big.Int
			}
		}
	}
	if _, err := asn1.Unmarshal(body, &req); err != nil || len(req.RequestList) != 1 {
		http.Error(w, "not a single-request OCSPRequest", http.StatusBadRequest)
		return
	}
	respDER, err := p.OCSPResponse(cliFetchT)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(respDER)
}

func TestOCSPFetchCLIHappyPath(t *testing.T) {
	var pki *testutil.PKI
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFetch(w, r, pki)
	}))
	defer srv.Close()
	p, err := testutil.NewPKI(testutil.Options{Now: cliFetchT, AIAOCSPURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pki = p
	served, err := p.OCSPResponse(cliFetchT)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := writePEM(t, dir, "signer.pem", p.Signer.PEM)
	chainPath := writePEM(t, dir, "chain.pem", p.Issuer.PEM, p.Root.PEM)
	outPath := filepath.Join(dir, "resp.der")

	code, out, serr := runExecuteChecked(t, []string{
		"ocsp", "fetch",
		"--cert", certPath,
		"--chain", chainPath,
		"--out", outPath,
	})
	if code != exitOK {
		t.Fatalf("exit %d, want 0 (stderr: %s)", code, serr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, served) {
		t.Error("output is not byte-exact with the served response")
	}
	if !strings.Contains(out, "producedAt=") || !strings.Contains(out, outPath) {
		t.Errorf("summary %q lacks producedAt / output path", out)
	}
}

func TestOCSPFetchCLIURLOverride(t *testing.T) {
	var pki *testutil.PKI
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFetch(w, r, pki)
	}))
	defer srv.Close()
	// The signer AIA is the default placeholder (nothing listens
	// there): success proves the --url override was used.
	p, err := testutil.NewPKI(testutil.Options{Now: cliFetchT})
	if err != nil {
		t.Fatal(err)
	}
	pki = p
	dir := t.TempDir()
	certPath := writePEM(t, dir, "signer.pem", p.Signer.PEM)
	issuerPath := writePEM(t, dir, "issuer.pem", p.Issuer.PEM)
	outPath := filepath.Join(dir, "resp.der")
	code, _, serr := runExecuteChecked(t, []string{
		"ocsp", "fetch",
		"--cert", certPath,
		"--issuer", issuerPath,
		"--url", srv.URL,
		"--out", outPath,
	})
	if code != exitOK {
		t.Fatalf("exit %d, want 0 (stderr: %s)", code, serr)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("output not written: %v", err)
	}
}

func TestOCSPFetchCLIUsageErrors(t *testing.T) {
	dir := t.TempDir()
	p, err := testutil.NewPKI(testutil.Options{Now: cliFetchT})
	if err != nil {
		t.Fatal(err)
	}
	certPath := writePEM(t, dir, "signer.pem", p.Signer.PEM)
	cases := []struct {
		name string
		args []string
		want string
		code int
	}{
		{"missing --cert", []string{"ocsp", "fetch", "--out", "x.der"}, "--cert is required", exitUsageErr},
		{"missing --out", []string{"ocsp", "fetch", "--cert", certPath}, "--out is required", exitUsageErr},
		{"cert with two certs", []string{"ocsp", "fetch", "--cert", writePEM(t, dir, "two.pem", p.Signer.PEM, p.Issuer.PEM), "--out", "x.der"}, "exactly one certificate", exitFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, serr := runExecuteChecked(t, tc.args)
			if code != tc.code {
				t.Fatalf("exit %d, want %d (stderr: %s)", code, tc.code, serr)
			}
			if !strings.Contains(serr, tc.want) {
				t.Errorf("stderr %q lacks %q", serr, tc.want)
			}
		})
	}
}

func TestOCSPFetchCLIResponderDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "responder is down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	p, err := testutil.NewPKI(testutil.Options{Now: cliFetchT})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := writePEM(t, dir, "signer.pem", p.Signer.PEM)
	issuerPath := writePEM(t, dir, "issuer.pem", p.Issuer.PEM)
	outPath := filepath.Join(dir, "resp.der")
	code, _, serr := runExecuteChecked(t, []string{
		"ocsp", "fetch",
		"--cert", certPath,
		"--issuer", issuerPath,
		"--url", srv.URL,
		"--out", outPath,
	})
	if code != exitFailed {
		t.Fatalf("exit %d, want %d (stderr: %s)", code, exitFailed, serr)
	}
	if !strings.Contains(serr, "500") || !strings.Contains(serr, "responder is down") {
		t.Errorf("stderr %q lacks 500 + server body", serr)
	}
}
