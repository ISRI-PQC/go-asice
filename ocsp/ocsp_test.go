// Hermetic tests of the ocsp package over an httptest responder. The
// responder re-derives the RFC 6960 section 4.1.1 CertID from the
// received request with an independent implementation (asn1 + sha1
// directly, no ocsp-package helpers) and rejects mismatches — the
// convention is pinned by this second implementation.
package ocsp_test

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/isri-pqc/go-asice/ocsp"
	ocspcrypto "github.com/isri-pqc/go-asice/ocsp/crypto"
	"github.com/isri-pqc/go-asice/testutil"
)

var fetchT = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// serveOCSP answers with a fresh "good" response for the PKI signer,
// after independently re-deriving the CertID from the request.
func serveOCSP(w http.ResponseWriter, r *http.Request, p *testutil.PKI, producedAt time.Time) {
	if r.Header.Get("Content-Type") != ocsp.ContentTypeRequest {
		http.Error(w, "content type "+r.Header.Get("Content-Type"), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Independent decode (RFC 6960 2.2 / 4.1.1, no ocsp-package types).
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
	if _, err := asn1.Unmarshal(body, &req); err != nil {
		http.Error(w, "unmarshal request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.RequestList) != 1 {
		http.Error(w, fmt.Sprintf("want exactly one request, got %d", len(req.RequestList)), http.StatusBadRequest)
		return
	}
	cid := req.RequestList[0].ReqCert
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	if !cid.HashAlgorithm.Algorithm.Equal(sha1OID) {
		http.Error(w, "hash algorithm "+cid.HashAlgorithm.Algorithm.String()+", want SHA-1 (1.3.14.3.2.26)", http.StatusBadRequest)
		return
	}
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(p.Issuer.Certificate.RawSubjectPublicKeyInfo, &spki); err != nil {
		http.Error(w, "issuer SPKI: "+err.Error(), http.StatusInternalServerError)
		return
	}
	wantName := sha1.Sum(p.Issuer.Certificate.RawSubject)
	wantKey := sha1.Sum(spki.Key.Bytes)
	if !bytes.Equal(cid.IssuerNameHash, wantName[:]) ||
		!bytes.Equal(cid.IssuerKeyHash, wantKey[:]) ||
		cid.SerialNumber.Cmp(p.Signer.Certificate.SerialNumber) != 0 {
		http.Error(w, "certID does not match the signer (RFC 6960 4.1.1)", http.StatusBadRequest)
		return
	}
	respDER, err := p.OCSPResponse(producedAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ocsp.ContentTypeResponse)
	w.Write(respDER)
}

func TestFetchAIA(t *testing.T) {
	var pki *testutil.PKI
	var served []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		old := w
		w2 := &capWriter{dst: &served, ResponseWriter: old}
		serveOCSP(w2, r, pki, fetchT)
	}))
	defer srv.Close()

	p, err := testutil.NewPKI(testutil.Options{Now: fetchT, AIAOCSPURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pki = p

	// AIA path: no URL supplied; the signer's AIA points at the server.
	// Issuer resolved from the chain.
	der, resp, err := ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		Chain:        []*x509.Certificate{p.Issuer.Certificate},
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Fetch (AIA): %v", err)
	}
	if !bytes.Equal(der, served) {
		t.Error("response is not byte-exact with the served bytes")
	}
	if resp.Status != 0 || resp.Basic == nil || !resp.Basic.Responses[0].Good() {
		t.Errorf("decoded response: status %d, basic %+v", resp.Status, resp.Basic)
	}
	if !resp.Basic.ProducedAt.Equal(fetchT) {
		t.Errorf("producedAt = %v, want %v", resp.Basic.ProducedAt, fetchT)
	}
	// certID in the response matches the RFC 6960 derivation.
	cid := resp.Basic.Responses[0].CertID
	if cid.SerialNumber.Cmp(p.Signer.Certificate.SerialNumber) != 0 {
		t.Error("response certID serial mismatch")
	}
}

type capWriter struct {
	dst *[]byte
	http.ResponseWriter
}

func (c *capWriter) Write(b []byte) (int, error) {
	*c.dst = append(*c.dst, b...)
	return c.ResponseWriter.Write(b)
}

func TestFetchURLOverride(t *testing.T) {
	var pki *testutil.PKI
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveOCSP(w, r, pki, fetchT)
	}))
	defer srv.Close()
	// The signer AIA is the default placeholder (nothing listens
	// there): a successful fetch proves the --url override was used.
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	pki = p
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		Issuer:       p.Issuer.Certificate,
		URL:          srv.URL,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Fetch (--url override): %v", err)
	}
}

func TestFetchNonSuccessfulStatus(t *testing.T) {
	// A malformedRequest response (responseStatus 1, no responseBytes).
	malformed, err := asn1.Marshal(struct {
		ResponseStatus asn1.Enumerated
	}{1})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocsp.ContentTypeResponse)
		w.Write(malformed)
	}))
	defer srv.Close()
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		Issuer:       p.Issuer.Certificate,
		URL:          srv.URL,
		Timeout:      5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "malformedRequest") {
		t.Fatalf("Fetch error = %v, want the malformedRequest failure", err)
	}
}

func TestFetchWrongResponseType(t *testing.T) {
	// successful status, but a foreign responseType.
	type foreignBytes struct {
		ResponseType asn1.ObjectIdentifier
		Response     []byte
	}
	type foreignResp struct {
		ResponseStatus asn1.Enumerated
		ResponseBytes  foreignBytes `asn1:"explicit,tag:0"`
	}
	foreignType, err := asn1.Marshal(foreignResp{
		ResponseStatus: 0,
		ResponseBytes:  foreignBytes{ResponseType: asn1.ObjectIdentifier{1, 2, 3, 4}, Response: []byte{0x05}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocsp.ContentTypeResponse)
		w.Write(foreignType)
	}))
	defer srv.Close()
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		Issuer:       p.Issuer.Certificate,
		URL:          srv.URL,
		Timeout:      5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "responseType") {
		t.Fatalf("Fetch error = %v, want the responseType failure", err)
	}
}

func TestFetchNoURL(t *testing.T) {
	// A certificate without an AIA and no URL: actionable error.
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	// The OCSP responder leaf has no AIA.
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.OCSPResponder.Certificate,
		Issuer:       p.Issuer.Certificate,
	})
	if err == nil || !strings.Contains(err.Error(), "no OCSP responder URL") {
		t.Fatalf("Fetch error = %v, want the no OCSP responder URL failure", err)
	}
}

func TestFetchNoIssuer(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		URL:          "http://127.0.0.1:1",
		Timeout:      5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "no issuer certificate") {
		t.Fatalf("Fetch error = %v, want the no issuer certificate failure", err)
	}
}

func TestFetchNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "responder is down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		Issuer:       p.Issuer.Certificate,
		URL:          srv.URL,
		Timeout:      5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "responder is down") {
		t.Fatalf("Fetch error = %v, want the 500 + server body", err)
	}
}

func TestFetchNoDigestModule(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: fetchT})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		Signer: p.Signer.Certificate,
		Issuer: p.Issuer.Certificate,
	})
	if err == nil || !strings.Contains(err.Error(), "requires the crypto modules") {
		t.Fatalf("Fetch error = %v, want the requires-the-crypto-modules failure", err)
	}
}

// TestFetchWrappedShapeFallback pins the responder-shape fallback: the
// responder accepts only the wrapped request shape (the canonical body
// inside one extra SEQUENCE — the reference implementation's
// convention, which rejects the bare canonical body with a 400). Fetch
// must reach it via the fallback after its canonical attempt is rejected.
func TestFetchWrappedShapeFallback(t *testing.T) {
	var pki *testutil.PKI
	var rejections int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cid, err := ocsp.CertIDForSigner(ocspcrypto.NewStdDigestModule(), pki.Signer.Certificate, pki.Issuer.Certificate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		canon, err := ocsp.Request{CertID: cid}.Encode()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		wrapped := derSeqTest(canon)
		if !bytes.Equal(body, wrapped) {
			rejections++
			http.Error(w, `{"detail":"bad request: invalid OCSPRequest"}`, http.StatusBadRequest)
			return
		}
		// serveOCSP decodes the canonical body: strip the wrapper
		// header first (short or long form).
		h := 2
		if body[1]&0x80 != 0 {
			h = 2 + int(body[1]&0x7f)
		}
		r.Body = io.NopCloser(bytes.NewReader(body[h:]))
		serveOCSP(w, r, pki, fetchT)
	}))
	defer srv.Close()

	p, err := testutil.NewPKI(testutil.Options{Now: fetchT, AIAOCSPURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pki = p
	der, resp, err := ocsp.Fetch(context.Background(), ocsp.FetchOptions{
		DigestModule: ocspcrypto.NewStdDigestModule(),
		Signer:       p.Signer.Certificate,
		Chain:        []*x509.Certificate{p.Issuer.Certificate},
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Fetch (wrapped-shape fallback): %v", err)
	}
	if len(der) == 0 {
		t.Error("no response bytes returned")
	}
	if rejections != 1 {
		t.Errorf("canonical-shape rejections = %d, want 1 (the fallback trigger)", rejections)
	}
	if resp.Status != 0 || resp.Basic == nil || !resp.Basic.Responses[0].Good() {
		t.Errorf("decoded response: status %d, basic %+v", resp.Status, resp.Basic)
	}
}

// derSeqTest wraps payload in a SEQUENCE (test-local, independent of the
// production encoders; the fixtures keep the payload short-form).
func derSeqTest(payload []byte) []byte {
	if len(payload) >= 0x80 {
		panic("derSeqTest: payload too long for the short form")
	}
	out := []byte{0x30, byte(len(payload))}
	return append(out, payload...)
}
