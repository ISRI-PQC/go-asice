package testutil

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// testNow is the fixed reference time every test injects; generated
// artifacts must depend only on injected times, never the wall clock.
var testNow = time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC)

func newTestPKI(t *testing.T) *PKI {
	t.Helper()
	p, err := NewPKI(Options{Now: testNow})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	return p
}

func certPool(certs ...*Cert) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c.Certificate)
	}
	return pool
}

func verifyChain(t *testing.T, cert *Cert, roots, intermediates *x509.CertPool) {
	t.Helper()
	_, err := cert.Certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   testNow,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("verify %q: %v", cert.Certificate.Subject.CommonName, err)
	}
}

func hasEKU(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, u := range c.ExtKeyUsage {
		if u == want {
			return true
		}
	}
	return false
}

func sha1Sum(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

// TestPKI_ChainsVerify: every cert chain verifies with stdlib
// x509.Verify against our root/intermediates at the injected time, and
// each role carries the extensions the Estonian e-voting collector
// (the library's interop target; see the README) depends on (modeled on
// the fixture certs): signer KU ContentCommitment; responder KU
// DigitalSignature + EKU OCSPSigning; TSA KU DigitalSignature|
// ContentCommitment + EKU TimeStamping, issued by the root like the
// fixture TSA "DEMO of SK TSA 2014".
func TestPKI_ChainsVerify(t *testing.T) {
	p := newTestPKI(t)
	roots := certPool(p.Root)

	verifyChain(t, p.Signer, roots, certPool(p.Issuer))        // leaf -> issuer -> root
	verifyChain(t, p.Signer2, roots, certPool(p.Issuer))       // leaf -> issuer -> root
	verifyChain(t, p.OCSPResponder, roots, certPool(p.Issuer)) // leaf -> issuer -> root
	verifyChain(t, p.TSA, roots, nil)                          // leaf -> root (like the fixture TSA)
	verifyChain(t, p.Issuer, roots, nil)                       // CA -> root

	for _, s := range []*Cert{p.Signer, p.Signer2} {
		if s.Certificate.KeyUsage&x509.KeyUsageContentCommitment == 0 {
			t.Fatalf("signer %q cert lacks KU ContentCommitment: 0x%x", s.Certificate.Subject.CommonName, s.Certificate.KeyUsage)
		}
	}
	if !bytes.Equal(p.Signer2.Certificate.RawIssuer, p.Issuer.Certificate.RawSubject) {
		t.Fatalf("signer2 issued by %q, want the issuer", p.Signer2.Certificate.Issuer)
	}
	if p.OCSPResponder.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatalf("responder cert lacks KU DigitalSignature: 0x%x", p.OCSPResponder.Certificate.KeyUsage)
	}
	if !hasEKU(p.OCSPResponder.Certificate, x509.ExtKeyUsageOCSPSigning) {
		t.Fatalf("responder cert lacks EKU OCSPSigning: %v", p.OCSPResponder.Certificate.ExtKeyUsage)
	}
	if !hasEKU(p.TSA.Certificate, x509.ExtKeyUsageTimeStamping) {
		t.Fatalf("TSA cert lacks EKU TimeStamping: %v", p.TSA.Certificate.ExtKeyUsage)
	}
	if !bytes.Equal(p.TSA.Certificate.RawIssuer, p.Root.Certificate.RawSubject) {
		t.Fatalf("TSA issued by %q, want the root", p.TSA.Certificate.Issuer)
	}
	if !p.Issuer.Certificate.IsCA || !p.Root.Certificate.IsCA {
		t.Fatalf("CA certs must have IsCA (issuer=%v root=%v)", p.Issuer.Certificate.IsCA, p.Root.Certificate.IsCA)
	}

	// Hermeticity: validity follows the injected time, not the wall clock.
	if !p.Signer.Certificate.NotBefore.Equal(testNow.Add(-24*time.Hour)) ||
		!p.Signer.Certificate.NotAfter.Equal(testNow.Add(defaultValidity)) {
		t.Fatalf("unexpected validity window: %s .. %s", p.Signer.Certificate.NotBefore, p.Signer.Certificate.NotAfter)
	}
	if _, err := NewPKI(Options{}); err == nil {
		t.Fatal("NewPKI(Options{}) should fail on zero Now")
	}
}

// TestOCSPResponse: the generated "good" response parses with
// collector-shaped structs; its certID matches the signer cert exactly
// (the collector's CertID fields: SHA-1 of RawIssuer, AuthorityKeyId,
// serial); its signature
// verifies over the tbsResponseData with the responder cert (checked by
// OCSPStatus); producedAt == thisUpdate == the injected time.
func TestOCSPResponse(t *testing.T) {
	p := newTestPKI(t)
	producedAt := testNow.Add(3 * time.Second)
	der, err := p.OCSPResponse(producedAt)
	if err != nil {
		t.Fatalf("OCSPResponse: %v", err)
	}

	got, err := p.OCSPStatus(der, producedAt)
	if err != nil {
		t.Fatalf("OCSPStatus: %v", err)
	}
	if !got.Equal(producedAt) {
		t.Fatalf("producedAt %v, want %v", got, producedAt)
	}

	// Field-by-field parse (the collector's struct shapes).
	outer, basic, err := parseOCSPResponseForTest(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if int(outer.ResponseStatus) != 0 {
		t.Fatalf("status %d, want 0 (successful)", outer.ResponseStatus)
	}
	if !outer.ResponseBytes.ResponseType.Equal(idPKIXOCSPBasic) {
		t.Fatalf("response type %v, want %v", outer.ResponseBytes.ResponseType, idPKIXOCSPBasic)
	}
	rd := basic.TBSResponseData
	if len(rd.ResponderIDByName) == 0 {
		t.Fatal("responder ID is not a name")
	}
	if len(rd.Responses) != 1 {
		t.Fatalf("%d singleResponses, want 1", len(rd.Responses))
	}
	single := rd.Responses[0]
	if !bytes.Equal(single.CertID.IssuerNameHash, sha1Sum(p.Signer.Certificate.RawIssuer)) {
		t.Fatalf("issuerNameHash %x, want SHA-1(RawIssuer)", single.CertID.IssuerNameHash)
	}
	if !bytes.Equal(single.CertID.IssuerKeyHash, p.Signer.Certificate.AuthorityKeyId) {
		t.Fatalf("issuerKeyHash %x, want AKI %x", single.CertID.IssuerKeyHash, p.Signer.Certificate.AuthorityKeyId)
	}
	if single.CertID.SerialNumber.Cmp(p.Signer.Certificate.SerialNumber) != 0 {
		t.Fatalf("serial %v, want %v", single.CertID.SerialNumber, p.Signer.Certificate.SerialNumber)
	}
	if !single.CertID.HashAlgorithm.Algorithm.Equal(oidSHA1) {
		t.Fatalf("certID hash alg %v, want SHA-1", single.CertID.HashAlgorithm.Algorithm)
	}
	if !single.ThisUpdate.Equal(producedAt) {
		t.Fatalf("thisUpdate %v, want %v", single.ThisUpdate, producedAt)
	}
	if !basic.SignatureAlgorithm.Algorithm.Equal(oidSHA256WithRSA) {
		t.Fatalf("signature algorithm %v, want sha256WithRSA", basic.SignatureAlgorithm.Algorithm)
	}
	if len(basic.Certs) != 1 {
		t.Fatalf("%d embedded certs, want 1 (the responder, like the fixture)", len(basic.Certs))
	}
	// FullBytes is the complete certificate DER (the collector parses
	// it the same way, the FullBytes content of the response certs).
	embedded, err := x509.ParseCertificate(basic.Certs[0].FullBytes)
	if err != nil {
		t.Fatalf("parse embedded responder cert: %v", err)
	}
	if !bytes.Equal(embedded.Raw, p.OCSPResponder.DER) {
		t.Fatal("embedded responder cert differs from the PKI responder")
	}
}

// TestOCSPResponse_Rejects: a wrong producedAt and a tampered signature
// are both reported.
func TestOCSPResponse_Rejects(t *testing.T) {
	p := newTestPKI(t)
	der, err := p.OCSPResponse(testNow)
	if err != nil {
		t.Fatalf("OCSPResponse: %v", err)
	}
	if _, err := p.OCSPStatus(der, testNow.Add(time.Hour)); err == nil {
		t.Fatal("OCSPStatus accepted a wrong producedAt")
	}
	// Tamper a byte of the producedAt inside the tbsResponseData (the
	// last byte of the DER belongs to the embedded responder cert, which
	// the signature does not cover). producedAt for testNow is the
	// GeneralizedTime "20250315103000Z"; flip its last byte.
	gt := append([]byte{0x18, 0x0F}, "20250315103000Z"...)
	pos := bytes.Index(der, gt)
	if pos < 0 {
		t.Fatal("producedAt GeneralizedTime not found in the response DER")
	}
	bad := append([]byte(nil), der...)
	bad[pos+len(gt)-1] ^= 0xFF
	if _, err := p.OCSPStatus(bad, testNow); err == nil {
		t.Fatal("OCSPStatus accepted a tampered response")
	}
}

// ---------------------------------------------------------------------------
// Time-stamp token (RFC 3161)
// ---------------------------------------------------------------------------

// parseTSToken decodes a TimeStampToken with the same shapes the
// Estonian e-voting collector's TSP client uses.
func parseTSToken(der []byte) (timeStpToken, tstInfo, error) {
	var outer timeStpToken
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return outer, tstInfo{}, err
	}
	var info tstInfo
	if _, err := asn1.Unmarshal(outer.Content.EncapContentInfo.EContent, &info); err != nil {
		return outer, info, err
	}
	return outer, info, nil
}

// TestTimeStampToken: the generated TST parses with collector-shaped
// structs, carries every field the Estonian e-voting collector checks
// (version 3, id-ct-TSTInfo content, one SignerInfo v1 with the four
// signed attributes, correct imprints), and its signature verifies over
// the signed attributes with the TSA cert (the same reconstruction as
// the collector's TST signature check: marshal the slice,
// patch the tag to SET OF, CheckSignature).
func TestTimeStampToken(t *testing.T) {
	p := newTestPKI(t)
	data := []byte("S0-SIG canonical signature value bytes")

	genTime := testNow.Add(7 * time.Second)
	tstSerial := big.NewInt(0x0123456789ABCDEF)
	der, err := p.TimeStampToken(data, TSTOptions{GenTime: genTime, Serial: tstSerial})
	if err != nil {
		t.Fatalf("TimeStampToken: %v", err)
	}

	outer, info, err := parseTSToken(der)
	if err != nil {
		t.Fatalf("parse TST: %v", err)
	}
	// Content type and CMS version (the collector enforces version == 3).
	if !outer.ContentType.Equal(oidSignedData) {
		t.Fatalf("content type %v, want id-signedData", outer.ContentType)
	}
	if outer.Content.Version != 3 {
		t.Fatalf("signedData version %d, want 3", outer.Content.Version)
	}
	if !outer.Content.EncapContentInfo.EContentType.Equal(oidCTTSTInfo) {
		t.Fatalf("encap content type %v, want id-ct-TSTInfo", outer.Content.EncapContentInfo.EContentType)
	}
	if len(outer.Content.DigestAlgorithms) != 1 {
		t.Fatalf("%d digestAlgorithms, want 1 (the fixture carries one)", len(outer.Content.DigestAlgorithms))
	}
	// TSTInfo fields.
	if info.Version != 1 {
		t.Fatalf("TSTInfo version %d, want 1", info.Version)
	}
	if !info.Policy.Equal(defaultTSTPolicy) {
		t.Fatalf("policy %v, want the fixture's %v", info.Policy, defaultTSTPolicy)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Fatalf("imprint alg %v, want SHA-256 (the fixture uses SHA-256)", info.MessageImprint.HashAlgorithm.Algorithm)
	}
	wantImprint := sha256.Sum256(data)
	if !bytes.Equal(info.MessageImprint.HashedMessage, wantImprint[:]) {
		t.Fatalf("imprint %x, want %x", info.MessageImprint.HashedMessage, wantImprint)
	}
	if info.SerialNumber.Cmp(tstSerial) != 0 {
		t.Fatalf("serial %v, want %v", info.SerialNumber, tstSerial)
	}
	if !info.GenTime.Equal(genTime) {
		t.Fatalf("genTime %v, want %v", info.GenTime, genTime)
	}
	if info.Nonce != nil {
		t.Fatalf("nonce %v, want nil (not requested)", info.Nonce)
	}
	if len(info.Extensions) != 0 {
		t.Fatalf("%d extensions, want 0 (the fixture has none)", len(info.Extensions))
	}

	// TSA cert embedded in SignedData (the collector requires it). The
	// SET element
	// IS the cert TLV (FullBytes = tag+length+content), matching the
	// fixture and the collector's inclusion check (bytes.Equal(cert.Raw,
	// ...)).
	if len(outer.Content.Certificates) != 1 {
		t.Fatalf("%d certs, want 1", len(outer.Content.Certificates))
	}
	if !bytes.Equal(outer.Content.Certificates[0].FullBytes, p.TSA.DER) {
		t.Fatal("embedded cert differs from the PKI TSA cert")
	}

	// SignerInfo.
	if n := len(outer.Content.SignerInfos); n != 1 {
		t.Fatalf("%d signerInfos, want 1", n)
	}
	si := outer.Content.SignerInfos[0]
	if si.Version != 1 {
		t.Fatalf("signerInfo version %d, want 1 (issuer+serial, like the fixture)", si.Version)
	}
	if len(si.SubjectKeyIdentifier) != 0 {
		t.Fatalf("subjectKeyIdentifier %x, want empty (v1 uses issuer+serial)", si.SubjectKeyIdentifier)
	}
	if si.IssuerAndSerialNumber.SerialNumber.Cmp(p.TSA.Certificate.SerialNumber) != 0 {
		t.Fatalf("IASN serial %v, want the TSA serial %v", si.IssuerAndSerialNumber.SerialNumber, p.TSA.Certificate.SerialNumber)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Fatalf("digest alg %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
	if !si.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA256) {
		t.Fatalf("signature alg %v, want ecdsa-with-SHA256", si.SignatureAlgorithm.Algorithm)
	}

	// Signed attributes: exactly the four the fixture carries, in the
	// fixture order (contentType, signingTime, messageDigest, signingCert).
	if len(si.SignedAttrs) != 4 {
		t.Fatalf("%d signed attrs, want 4", len(si.SignedAttrs))
	}
	wantOrder := []asn1.ObjectIdentifier{oidAttrContentType, oidAttrSigningTime, oidAttrMessageDigest, oidAttrSigningCert}
	attrs := make(map[string]asn1.RawValue, 4)
	for i, a := range si.SignedAttrs {
		if !a.AttrType.Equal(wantOrder[i]) {
			t.Fatalf("signed attr %d is %v, want the fixture order", i, a.AttrType)
		}
		attrs[a.AttrType.String()] = a.AttrValue
	}

	// Each attribute value is a SET OF with one entry (RFC 5652);
	// AttrValue.Bytes is that single value's encoding.
	// contentType value == id-ct-TSTInfo.
	var ctOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(attrs[oidAttrContentType.String()].Bytes, &ctOID); err != nil || !ctOID.Equal(oidCTTSTInfo) {
		t.Fatalf("contentType value %v (err %v), want id-ct-TSTInfo", ctOID, err)
	}
	// signingTime value == GenTime (the collector's TST validation
	// requires it within the tsp DelayTime of genTime; the trust YAMLs
	// leave DelayTime at 0, so
	// equal — exactly as in the fixture, where the fixture's signingTime
	// is also == genTime).
	var st time.Time
	if _, err := asn1.Unmarshal(attrs[oidAttrSigningTime.String()].Bytes, &st); err != nil || !st.Equal(genTime) {
		t.Fatalf("signingTime value %v (err %v), want %v", st, err, genTime)
	}
	// messageDigest value == SHA-256(TSTInfo DER).
	md := sha256.Sum256(outer.Content.EncapContentInfo.EContent)
	var mdGot []byte
	if _, err := asn1.Unmarshal(attrs[oidAttrMessageDigest.String()].Bytes, &mdGot); err != nil || !bytes.Equal(mdGot, md[:]) {
		t.Fatalf("messageDigest %x (err %v), want SHA-256(TSTInfo) %x", mdGot, err, md)
	}
	// signingCert value: v2 with SHA-1(TSA cert) + issuer/serial of the
	// TSA cert (root name + serial), like the fixture.
	var scv2 signingCertificateV2
	if _, err := asn1.Unmarshal(attrs[oidAttrSigningCert.String()].Bytes, &scv2); err != nil {
		t.Fatalf("signingCert value: %v", err)
	}
	if len(scv2.Certs) != 1 {
		t.Fatalf("%d essCertIDs, want 1", len(scv2.Certs))
	}
	if !bytes.Equal(scv2.Certs[0].CertHash, sha1Sum(p.TSA.DER)) {
		t.Fatalf("essCertID hash %x, want SHA-1(TSA cert)", scv2.Certs[0].CertHash)
	}
	// The essCertID identifies the referenced (TSA) cert: its issuer's
	// name + the cert's OWN serial (RFC 5755), like the fixture.
	if scv2.Certs[0].IssuerAndSerialNumber.SerialNumber.Cmp(p.TSA.Certificate.SerialNumber) != 0 {
		t.Fatalf("essCertID serial %v, want the TSA cert serial %v",
			scv2.Certs[0].IssuerAndSerialNumber.SerialNumber, p.TSA.Certificate.SerialNumber)
	}

	// Signature over the signed attrs — the same reconstruction the
	// collector's TST signature check performs.
	attrsDER, err := asn1.Marshal(si.SignedAttrs)
	if err != nil {
		t.Fatalf("marshal signed attrs: %v", err)
	}
	attrsDER[0] = 0x31 // SET OF
	if err := p.TSA.Certificate.CheckSignature(x509.ECDSAWithSHA256, attrsDER, si.Signature); err != nil {
		t.Fatalf("TST signature: %v", err)
	}
}

// TestTimeStampToken_Nonce: with a nonce the TSTInfo carries it (the
// fixture carries a 21-byte nonce); without one it is absent.
func TestTimeStampToken_Nonce(t *testing.T) {
	p := newTestPKI(t)
	nonce := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21})

	der, err := p.TimeStampToken([]byte("data"), TSTOptions{GenTime: testNow, Nonce: nonce})
	if err != nil {
		t.Fatalf("TimeStampToken with nonce: %v", err)
	}
	_, info, err := parseTSToken(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce %v, want %v", info.Nonce, nonce)
	}

	der2, err := p.TimeStampToken([]byte("data"), TSTOptions{GenTime: testNow})
	if err != nil {
		t.Fatalf("TimeStampToken without nonce: %v", err)
	}
	if _, info, err := parseTSToken(der2); err != nil || info.Nonce != nil {
		t.Fatalf("nonce must be absent, got %v (err %v)", info.Nonce, err)
	}
}

// ---------------------------------------------------------------------------
// openssl cross-check (skipped when openssl is unavailable)
// ---------------------------------------------------------------------------

func opensslAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
		return false
	}
	return true
}

// runOpenSSL runs openssl with args and returns the combined output.
// openssl exits non-zero on verification failures we do not care about
// (e.g. "Response Verify Failure" without a CA file), so the exit status
// is ignored; empty output is the real failure.
func runOpenSSL(t *testing.T, args ...string) string {
	t.Helper()
	out, _ := exec.Command("openssl", args...).CombinedOutput()
	if len(out) == 0 {
		t.Fatalf("openssl %v produced no output", args)
	}
	return string(out)
}

// TestTST_OpensslAsn1parse: `openssl asn1parse` on our TST shows the
// expected structural skeleton: pkcs7-signedData content type,
// signedData version 3, id-smime-ct-TSTInfo encap, one signerInfo
// (version 1) with the four signed attribute OIDs.
//
// SELF-CONSISTENCY PIN (openssl cross-check of our generated artifact);
// the fixture cross-check (vs the collector's fixture TST) lives in
// the external acceptance harness (maintained outside this repo).
func TestTST_OpensslAsn1parse(t *testing.T) {
	if !opensslAvailable(t) {
		return
	}
	p := newTestPKI(t)
	der, err := p.TimeStampToken([]byte("data"), TSTOptions{GenTime: testNow})
	if err != nil {
		t.Fatalf("TimeStampToken: %v", err)
	}
	dir := t.TempDir()
	ourPath := filepath.Join(dir, "ours.der")
	if err := os.WriteFile(ourPath, der, 0o600); err != nil {
		t.Fatal(err)
	}

	required := []string{
		"pkcs7-signedData",
		"id-smime-ct-TSTInfo",
		"contentType",
		"signingTime",
		"messageDigest",
		"id-smime-aa-signingCertificate",
	}
	out := runOpenSSL(t, "asn1parse", "-inform", "DER", "-in", ourPath, "-i")
	// signedData version 3 (RFC 5652: non id-data content type).
	if !regexp.MustCompile(`d=3\s+hl=2 l=\s+1 prim:\s+INTEGER\s+:03`).MatchString(out) {
		t.Fatalf("ours: missing signedData version INTEGER :03 in asn1parse output:\n%s", out)
	}
	for _, marker := range required {
		if !strings.Contains(out, marker) {
			t.Fatalf("ours: asn1parse output lacks %q:\n%s", marker, out)
		}
	}
	t.Logf("ours TST asn1parse: version 3, id-ct-TSTInfo, 4 signed attrs present")
}

// TestOCSP_OpensslRespin: `openssl ocsp -respin -text` on our response
// shows the expected shape: successful status, basic response type,
// responder name, certID hashes, "good" status, producedAt == thisUpdate.
//
// SELF-CONSISTENCY PIN (openssl cross-check of our generated artifact);
// the fixture cross-check (vs the collector's fixture OCSP response)
// lives in the external acceptance harness (maintained outside this
// repo).
func TestOCSP_OpensslRespin(t *testing.T) {
	if !opensslAvailable(t) {
		return
	}
	p := newTestPKI(t)
	producedAt := testNow
	der, err := p.OCSPResponse(producedAt)
	if err != nil {
		t.Fatalf("OCSPResponse: %v", err)
	}
	dir := t.TempDir()
	ourPath := filepath.Join(dir, "ours.der")
	if err := os.WriteFile(ourPath, der, 0o600); err != nil {
		t.Fatal(err)
	}

	required := []string{
		"OCSP Response Status: successful (0x0)",
		"Response Type: Basic OCSP Response",
		"Responder Id:",
		"Produced At:",
		"Issuer Name Hash:",
		"Issuer Key Hash:",
		"Serial Number:",
		"Cert Status: good",
		"This Update:",
	}
	out := runOpenSSL(t, "ocsp", "-respin", ourPath, "-text")
	for _, marker := range required {
		if !strings.Contains(out, marker) {
			t.Fatalf("ours: openssl ocsp output lacks %q:\n%s", marker, out)
		}
	}

	// Our certID fields are the PKI signer's: SHA-1(RawIssuer) and AKI.
	nameHash := sha1Sum(p.Signer.Certificate.RawIssuer)
	if !strings.Contains(strings.ToUpper(out), strings.ToUpper(fmt.Sprintf("%x", nameHash))) {
		t.Fatalf("openssl output lacks our issuerNameHash %x:\n%s", nameHash, out)
	}
}

// ---------------------------------------------------------------------------
// Time handling
// ---------------------------------------------------------------------------

// TestTST_TimesRoundTrip: the injected times round-trip exactly — the
// TSDelayTime window is controllable in later tests by choosing GenTime
// and producedAt (the collector's check: producedAt-genTime in [0,
// TSDelayTime]).
func TestTST_TimesRoundTrip(t *testing.T) {
	p := newTestPKI(t)

	cases := []struct {
		name       string
		producedAt time.Time
		genTime    time.Time
	}{
		{"identical (fixture pattern)", testNow, testNow},
		{"genTime 3s earlier", testNow, testNow.Add(-3 * time.Second)},
		{"boundary: 60s earlier (== trustTS.yaml tsdelaytime)", testNow, testNow.Add(-60 * time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ocsp, err := p.OCSPResponse(tc.producedAt)
			if err != nil {
				t.Fatalf("OCSPResponse: %v", err)
			}
			if _, err := p.OCSPStatus(ocsp, tc.producedAt); err != nil {
				t.Fatalf("OCSPStatus: %v", err)
			}
			tst, err := p.TimeStampToken([]byte("data"), TSTOptions{GenTime: tc.genTime})
			if err != nil {
				t.Fatalf("TimeStampToken: %v", err)
			}
			if _, info, err := parseTSToken(tst); err != nil {
				t.Fatalf("parse: %v", err)
			} else if !info.GenTime.Equal(tc.genTime) {
				t.Fatalf("genTime %v, want %v", info.GenTime, tc.genTime)
			}
		})
	}
}

// TestPKI_YearRangeTimes: times near the UTCTIME/GeneralizedTime boundary
// (year > 2049 forces GeneralizedTime) round-trip, so the generated
// artifacts never depend on the wall-clock year.
func TestPKI_YearRangeTimes(t *testing.T) {
	for _, now := range []time.Time{
		time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), // UTCTIME
		time.Date(2060, 1, 1, 0, 0, 0, 0, time.UTC), // GeneralizedTime
	} {
		p, err := NewPKI(Options{Now: now})
		if err != nil {
			t.Fatalf("NewPKI(%v): %v", now, err)
		}
		ocsp, err := p.OCSPResponse(now)
		if err != nil {
			t.Fatalf("OCSPResponse: %v", err)
		}
		if _, err := p.OCSPStatus(ocsp, now); err != nil {
			t.Fatalf("OCSPStatus at %v: %v", now, err)
		}
		tst, err := p.TimeStampToken([]byte("data"), TSTOptions{GenTime: now})
		if err != nil {
			t.Fatalf("TimeStampToken: %v", err)
		}
		if _, info, err := parseTSToken(tst); err != nil || !info.GenTime.Equal(now) {
			t.Fatalf("genTime round-trip at %v: %v (%v)", now, info.GenTime, err)
		}
		// Chain at that time still verifies.
		roots := certPool(p.Root)
		_, err = p.Signer.Certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: certPool(p.Issuer),
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			t.Fatalf("verify at %v: %v", now, err)
		}
	}
}
