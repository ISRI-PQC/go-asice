// Package asic — unit tests of the self-verifier (T8a BES core + T8b
// TS profile): the smoke case (our 1-file container passes every BES
// check) plus one negative per check (structure, digest, signature
// value, signed properties, TM rejection, SHA-1 rejection, TS profile
// checks — TST imprint, TSDelayTime, OCSP certID, USP shape — and
// trust setup). The fixture matrix against the collector lives in the
// external acceptance harness (maintained outside this repo).

package asic

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"hash/crc32"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	asiccrypto "github.com/isri-pqc/go-asice/asic/crypto"
	"github.com/isri-pqc/go-asice/testutil"
)

// verifyT is the single reference time of these unit tests (PKI
// reference time and every SigningTime), mirroring the acceptance
// single-clock rule (ADR 0001 §6).
var verifyT = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

// verifyHarness is the shared unit fixture: a hermetic PKI and the
// good 1-file, 1-signature BES container built by asic primitives.
type verifyHarness struct {
	pki  *testutil.PKI
	docs []Doc
	sig  []byte
	good []byte
	// parsed trust certs for the standard TST verifier (the testutil
	// PKI equivalents of trustTS.yaml's tsp.signers / intermediates).
	tstSigners    []*x509.Certificate
	intermediates []*x509.Certificate
}

func newVerifyHarness(t *testing.T) *verifyHarness {
	t.Helper()
	p, err := testutil.NewPKI(testutil.Options{Now: verifyT})
	if err != nil {
		t.Fatal(err)
	}
	tstSigners, err := ParsePEMCerts(p.TSA.PEM)
	if err != nil {
		t.Fatalf("TSA PEM: %v", err)
	}
	intermediates, err := ParsePEMCerts(p.Issuer.PEM)
	if err != nil {
		t.Fatalf("Issuer PEM: %v", err)
	}
	docs := []Doc{{Name: "test.txt", MediaType: "application/octet-stream", Data: []byte("verify data")}}
	sig, err := SignBES(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, verifyT)
	if err != nil {
		t.Fatalf("SignBES: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteContainer(&buf, docs, sig); err != nil {
		t.Fatalf("WriteContainer: %v", err)
	}
	return &verifyHarness{
		pki: p, docs: docs, sig: sig, good: buf.Bytes(),
		tstSigners:    tstSigners,
		intermediates: intermediates,
	}
}

// opts returns VerifyOptions over the harness's hermetic trust (the
// standard crypto modules).
func (h *verifyHarness) opts() VerifyOptions {
	return besVerifyOptions(h.pki.Root.PEM, h.pki.Issuer.PEM)
}

// path writes container bytes to a fresh file and returns its path.
func (h *verifyHarness) path(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "container.bdoc")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// expectFail runs Verify over data and asserts a FAIL verdict whose
// signature (or container) errors contain want.
func expectFail(t *testing.T, path string, opts VerifyOptions, want string) *Report {
	t.Helper()
	rep, err := Verify(path, opts)
	if err != nil {
		t.Fatalf("Verify hard error: %v", err)
	}
	if rep.OK {
		t.Fatalf("expected FAIL, got PASS")
	}
	joined := strings.Join(rep.Errors, "\n")
	for i := range rep.Signatures {
		joined += "\n" + strings.Join(rep.Signatures[i].Errors, "\n")
	}
	if !strings.Contains(joined, want) {
		t.Fatalf("expected an error containing %q, got: %s", want, joined)
	}
	return rep
}

// TestVerifyBESPass is the smoke case: our 1-file BES container passes
// structure + digests + C14N + crypto + chain + signed properties.
func TestVerifyBESPass(t *testing.T) {
	h := newVerifyHarness(t)
	rep, err := Verify(h.path(t, h.good), h.opts())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("expected PASS, got FAIL: %v / %v", rep.Errors, sigErrors(rep))
	}
	if len(rep.Signatures) != 1 {
		t.Fatalf("signatures: got %d, want 1", len(rep.Signatures))
	}
	s := rep.Signatures[0]
	if s.ID != "S0" || !s.OK || len(s.Errors) != 0 {
		t.Errorf("S0 report: %+v", s)
	}
	if !s.SigningTime.Equal(verifyT) {
		t.Errorf("SigningTime: got %v, want %v", s.SigningTime, verifyT)
	}
	if s.Signer == "" {
		t.Error("Signer name is empty")
	}
	if len(rep.DataFiles) != 1 || rep.DataFiles[0] != "test.txt" {
		t.Errorf("DataFiles: %v", rep.DataFiles)
	}
}

func sigErrors(rep *Report) []string {
	var out []string
	for _, s := range rep.Signatures {
		out = append(out, s.Errors...)
	}
	return out
}

// TestVerifyDataFileTamper: one flipped byte of a data file must fail
// with a digest mismatch (the signature still verifies — the failure
// lands in the reference digests, like the collector's file-reference
// digest rejection).
func TestVerifyDataFileTamper(t *testing.T) {
	h := newVerifyHarness(t)
	bad := flipStoredEntryByte(t, h.good, "test.txt", 0, func(c byte) byte { return c ^ 0xFF })
	expectFail(t, h.path(t, bad), h.opts(), "digest mismatch for file \"test.txt\"")
}

// TestVerifySignatureValueTamper: one flipped base64 character of the
// S0 SignatureValue must fail signature verification.
func TestVerifySignatureValueTamper(t *testing.T) {
	h := newVerifyHarness(t)
	marker := []byte(`Id="S0-SIG">`)
	idx := bytes.Index(h.sig, marker)
	if idx < 0 {
		t.Fatal("SignatureValue Id marker not found")
	}
	off := idx + len(marker) // first base64 character of the value
	bad := flipStoredEntryByte(t, h.good, "META-INF/signatures0.xml", off, func(c byte) byte {
		if c == 'X' {
			return 'Y'
		}
		return 'X'
	})
	rep := expectFail(t, h.path(t, bad), h.opts(), "signature verification failed")
	for _, e := range rep.Signatures[0].Errors {
		if strings.Contains(e, "digest mismatch for file") {
			t.Errorf("file digest must still verify (tamper is in the signature value): %v", e)
		}
	}
}

// TestVerifyStructureRejections: container-structure failures mirror
// the collector's container/manifest rejection taxonomy (documented
// in the external acceptance harness, maintained outside this repo).
func TestVerifyStructureRejections(t *testing.T) {
	h := newVerifyHarness(t)
	manifest, err := manifestXML(h.docs)
	if err != nil {
		t.Fatal(err)
	}
	emptyManifest, err := manifestXML([]Doc{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		entries []miniEntry
		want    string
	}{
		{
			name: "WrongMimeType",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte("application/zip")},
				{Name: "META-INF/manifest.xml", Data: manifest},
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "mimetype content is",
		},
		{
			name: "MimeTypeNotFirst",
			entries: []miniEntry{
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "META-INF/manifest.xml", Data: manifest},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "first entry is not the \"mimetype\" magic file",
		},
		{
			name: "MissingManifest",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "missing META-INF/manifest.xml",
		},
		{
			name: "UnknownMetaInfEntry",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "META-INF/manifest.xml", Data: manifest},
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: "META-INF/other.xml", Data: []byte("<other/>")},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "unknown META-INF entry",
		},
		{
			name: "DataFileInSubfolder",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "META-INF/manifest.xml", Data: manifest},
				{Name: "sub/test.txt", Data: h.docs[0].Data},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "in a subfolder",
		},
		{
			name: "DuplicateEntryName",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "META-INF/manifest.xml", Data: manifest},
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: "test.txt", Data: []byte("again")},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "duplicate entry name",
		},
		{
			name: "NoDataFiles",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "META-INF/manifest.xml", Data: emptyManifest},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
			want: "no data files",
		},
		{
			name: "NoSignatureFiles",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: "META-INF/manifest.xml", Data: manifest},
				{Name: "test.txt", Data: h.docs[0].Data},
			},
			want: "no signature files",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFail(t, h.path(t, miniStoredZIP(tc.entries)), h.opts(), tc.want)
		})
	}
}

// TestVerifySignaturePolicyRejected: a SignaturePolicyIdentifier inside
// the SignedProperties (TM shape) must be rejected, like the
// collector does in the BES and TS profiles.
func TestVerifySignaturePolicyRejected(t *testing.T) {
	h := newVerifyHarness(t)
	marker := []byte("</xades:SigningCertificate>")
	idx := bytes.Index(h.sig, marker)
	if idx < 0 {
		t.Fatal("SigningCertificate marker not found")
	}
	spi := []byte("\n            <xades:SignaturePolicyIdentifier>\n              <xades:SignaturePolicyId>\n                <xades:SigPolicyId>\n                  <xades:Identifier Qualifier=\"OIDAsURN\">urn:oid:1.3.6.1.4.1.10015.1000.3.2.1</xades:Identifier>\n                </xades:SigPolicyId>\n              </xades:SignaturePolicyId>\n            </xades:SignaturePolicyIdentifier>")
	sig2 := append(append([]byte(nil), h.sig[:idx+len(marker)]...), spi...)
	sig2 = append(sig2, h.sig[idx+len(marker):]...)

	var buf bytes.Buffer
	if err := WriteContainer(&buf, h.docs, sig2); err != nil {
		t.Fatal(err)
	}
	rep := expectFail(t, h.path(t, buf.Bytes()), h.opts(), "SignaturePolicyIdentifier present")
	// The injected SPI also breaks the SignedProperties digest: both
	// errors must be reported.
	joined := strings.Join(rep.Signatures[0].Errors, "\n")
	if !strings.Contains(joined, "SignedProperties digest mismatch") {
		t.Errorf("the SP digest must also mismatch, got: %v", rep.Signatures[0].Errors)
	}
}

// TestVerifySHA1Rejected: a SHA-1-signed signer certificate must be
// rejected with the clear "SHA-1 signature unsupported" error (the
// testEIDBES fixture behavior; Go >= 1.24 cannot verify SHA-1 chains).
func TestVerifySHA1Rejected(t *testing.T) {
	h := newVerifyHarness(t)
	leaf, rootPEM, interPEM := sha1Chain(t)
	docs := []Doc{{Name: "test.txt", MediaType: "application/octet-stream", Data: []byte("sha1 data")}}
	sig, err := SignBES(0, stdSignerModule(t, leaf.key), stdDigestModule(), leaf.cert, docs, verifyT)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteContainer(&buf, docs, sig); err != nil {
		t.Fatal(err)
	}
	expectFail(t, h.path(t, buf.Bytes()), besVerifyOptions(rootPEM, interPEM), "SHA-1 signature unsupported")
}

// --- TS profile (T8b) ---

// tsOpts returns TS-profile VerifyOptions over the harness trust (the
// PKI root/issuer, the TSA signer pool on the standard TST verifier,
// and the OCSP responder — the testutil PKI equivalents of
// trustTS.yaml's roots/intermediates/tsp.signers/ocsp.responders).
func (h *verifyHarness) tsOpts() VerifyOptions {
	o := stdVerifyOptions(ProfileTS)
	o.RootsPEM = h.pki.Root.PEM
	o.IntermediatesPEM = h.pki.Issuer.PEM
	o.OCSPRespondersPEM = h.pki.OCSPResponder.PEM
	o.TSTVerifier = asiccrypto.NewStdTSTVerifierModule(h.tstSigners, h.intermediates)
	return o
}

// tsData returns the asic.TSData for the harness PKI: a TST covering
// the supplied data (or stamp when non-nil) generated at genTime, plus
// a "good" OCSP response for the signer at ocspTime.
func (h *verifyHarness) tsData(t *testing.T, stamp []byte, genTime, ocspTime time.Time) TSData {
	t.Helper()
	ocsp, err := h.pki.OCSPResponse(ocspTime)
	if err != nil {
		t.Fatal(err)
	}
	return TSData{
		TimeStamp: func(d []byte) ([]byte, error) {
			if stamp != nil {
				d = stamp
			}
			return h.pki.TimeStampToken(d, testutil.TSTOptions{GenTime: genTime})
		},
		OCSPResponse: ocsp,
		Certificates: []*x509.Certificate{h.pki.OCSPResponder.Certificate, h.pki.Issuer.Certificate},
	}
}

// signTSContainer renders a TS-profile container (1 data file, S0) and
// returns the container bytes.
func (h *verifyHarness) signTSContainer(t *testing.T, ts TSData) []byte {
	t.Helper()
	sig, err := SignTS(0, stdSignerModule(t, h.pki.Signer.PrivateKey), stdDigestModule(), h.pki.Signer.Certificate, h.docs, verifyT, ts)
	if err != nil {
		t.Fatalf("SignTS: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteContainer(&buf, h.docs, sig); err != nil {
		t.Fatalf("WriteContainer: %v", err)
	}
	return buf.Bytes()
}

// TestVerifyTSPass is the TS smoke case: our 1-file TS container (TST
// over the canonical ds:SignatureValue + good OCSP at the same
// single time T) passes every BES + TS check, and the report
// SigningTime is the TST genTime (the collector's timestamp-check
// replacement).
func TestVerifyTSPass(t *testing.T) {
	h := newVerifyHarness(t)
	rep, err := Verify(h.path(t, h.signTSContainer(t, h.tsData(t, nil, verifyT, verifyT))), h.tsOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("expected PASS, got FAIL: %v / %v", rep.Errors, sigErrors(rep))
	}
	s := rep.Signatures[0]
	if !s.OK || len(s.Errors) != 0 {
		t.Errorf("S0 TS report: %+v", s)
	}
	if !s.SigningTime.Equal(verifyT) {
		t.Errorf("SigningTime: got %v, want %v (TST genTime)", s.SigningTime, verifyT)
	}
}

// TestVerifyTSMissingUnsignedProperties: a BES container (no
// xades:UnsignedProperties) under the TS profile must fail — the
// signature time-stamp is required (the collector's timestamp-missing
// rejection).
func TestVerifyTSMissingUnsignedProperties(t *testing.T) {
	h := newVerifyHarness(t)
	expectFail(t, h.path(t, h.good), h.tsOpts(), "signature time-stamp is required for the TS profile")
}

// TestVerifyTSWrongImprint: a TST whose imprint covers other data than
// the canonical ds:SignatureValue must fail (the collector's
// timestamp-verification error / tsp message-imprint mismatch).
func TestVerifyTSWrongImprint(t *testing.T) {
	h := newVerifyHarness(t)
	expectFail(t, h.path(t, h.signTSContainer(t, h.tsData(t, []byte("different data"), verifyT, verifyT))), h.tsOpts(), "signature time-stamp verification failed")
}

// TestVerifyTSStaleGenTime: a TST whose genTime PREDATES the OCSP
// producedAt by more than TSDelayTime (60 s) must fail the
// TSDelayTime bound (the only stale-TST defense — the offline TST
// check never inspects genTime against now).
func TestVerifyTSStaleGenTime(t *testing.T) {
	h := newVerifyHarness(t)
	expectFail(t, h.path(t, h.signTSContainer(t, h.tsData(t, nil, verifyT.Add(-5*time.Minute), verifyT))), h.tsOpts(), "TSDelayTime bound")
}

// TestVerifyTSOCSPBeforeGenTime: an OCSP producedAt MORE than
// TSDelayTime before the TST genTime must fail the same bound (the
// negative difference; the testOCSPOld.bdoc fixture shape).
func TestVerifyTSOCSPBeforeGenTime(t *testing.T) {
	h := newVerifyHarness(t)
	expectFail(t, h.path(t, h.signTSContainer(t, h.tsData(t, nil, verifyT, verifyT.Add(-2*time.Minute)))), h.tsOpts(), "TSDelayTime bound")
}

// TestVerifyTSOCSPWrongCertID: an OCSP response for a DIFFERENT
// certificate (another PKI's signer) must fail the certID match.
func TestVerifyTSOCSPWrongCertID(t *testing.T) {
	h := newVerifyHarness(t)
	other, err := testutil.NewPKI(testutil.Options{Now: verifyT})
	if err != nil {
		t.Fatal(err)
	}
	ocsp, err := other.OCSPResponse(verifyT)
	if err != nil {
		t.Fatal(err)
	}
	ts := h.tsData(t, nil, verifyT, verifyT)
	ts.OCSPResponse = ocsp
	expectFail(t, h.path(t, h.signTSContainer(t, ts)), h.tsOpts(), "certID does not match the signer certificate")
}

// TestVerifyTSMissingTST: a TS container whose SignatureTimeStamp
// element was removed must fail — the TST is required for the TS
// profile (the collector's timestamp-missing rejection on an empty
// EncapsulatedTimeStamp).
func TestVerifyTSMissingTST(t *testing.T) {
	h := newVerifyHarness(t)
	sig, err := SignTS(0, stdSignerModule(t, h.pki.Signer.PrivateKey), stdDigestModule(), h.pki.Signer.Certificate, h.docs, verifyT, h.tsData(t, nil, verifyT, verifyT))
	if err != nil {
		t.Fatal(err)
	}
	// Layout-agnostic strip (the signature document is serialized compact:
	// the xmlsig builder signs the live tree and bakes no layout into it).
	stripTST := regexp.MustCompile(`(?s)<xades:SignatureTimeStamp[^>]*>.*?</xades:SignatureTimeStamp>`)
	mod := stripTST.ReplaceAll(sig, nil)
	if bytes.Equal(mod, sig) {
		t.Fatal("TST element not found in the rendered signature")
	}
	var buf bytes.Buffer
	if err := WriteContainer(&buf, h.docs, mod); err != nil {
		t.Fatal(err)
	}
	expectFail(t, h.path(t, buf.Bytes()), h.tsOpts(), "xades:SignatureTimeStamp missing")
}

// TestVerifyTSProfileTrustSetup: a TS-profile request without the TS
// crypto modules must be a hard error (verification cannot start).
func TestVerifyTSProfileTrustSetup(t *testing.T) {
	h := newVerifyHarness(t)
	// Base modules wired, but the TS crypto modules (OCSPModule,
	// TSTVerifier) missing: verification cannot start.
	o := stdVerifyOptions(ProfileTS)
	o.RootsPEM = h.pki.Root.PEM
	_, err := Verify(h.path(t, h.good), o)
	if err == nil || !strings.Contains(err.Error(), "TS crypto modules") {
		t.Fatalf("expected the TS trust-setup error, got: %v", err)
	}
}

// TestVerifyTrustSetup: missing trust anchors and malformed PEM must be
// hard errors (verification cannot start).
func TestVerifyTrustSetup(t *testing.T) {
	h := newVerifyHarness(t)
	p := h.path(t, h.good)
	if _, err := Verify(p, VerifyOptions{}); err == nil {
		t.Fatal("expected a hard error with no trust anchors")
	}
	if _, err := Verify(p, VerifyOptions{RootsPEM: []byte("not pem")}); err == nil {
		t.Fatal("expected a hard error with no parseable roots")
	}
}

// --- legacy SHA-1 chain (mirrors the testEIDBES fixture shape) ---

// sha1Leaf pairs the SHA-1-signed leaf certificate with its key.
type sha1Leaf struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// sha1Chain builds a root (RSA, SHA-1 self-signed) → intermediate
// (RSA, SHA-1 signed) → leaf (ECDSA P-256 key, SHA-1 signed by the
// intermediate) chain, the testEIDBES fixture shape.
func sha1Chain(t *testing.T) (sha1Leaf, []byte, []byte) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TEST SHA-1 ROOT"},
		NotBefore:             verifyT.Add(-24 * time.Hour),
		NotAfter:              verifyT.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "TEST SHA-1 INTERMEDIATE"},
		NotBefore:             verifyT.Add(-24 * time.Hour),
		NotAfter:              verifyT.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootTmpl, intKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{CommonName: "TEST SHA-1 LEAF"},
		NotBefore:          verifyT.Add(-24 * time.Hour),
		NotAfter:           verifyT.Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageContentCommitment,
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return sha1Leaf{cert: leafCert, key: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})
}

// --- minimal stored-ZIP helpers (unit-scope variants of the acceptance
// helpers) ---

// miniEntry is one stored archive member for miniStoredZIP.
type miniEntry struct {
	Name string
	Data []byte
}

// miniStoredZIP assembles a valid stored (uncompressed) ZIP exactly
// like asic/zipwriter.go does (local headers, central directory, EOCD,
// fixed DOS date, no data descriptors).
func miniStoredZIP(entries []miniEntry) []byte {
	var b []byte
	offsets := make([]int, len(entries))
	for i := range entries {
		e := &entries[i]
		offsets[i] = len(b)
		var lh [30]byte
		binary.LittleEndian.PutUint32(lh[0:4], 0x04034b50)
		binary.LittleEndian.PutUint16(lh[4:6], 20)
		binary.LittleEndian.PutUint16(lh[10:12], 0) // stored
		binary.LittleEndian.PutUint32(lh[14:18], crc32.ChecksumIEEE(e.Data))
		binary.LittleEndian.PutUint32(lh[18:22], uint32(len(e.Data)))
		binary.LittleEndian.PutUint32(lh[22:26], uint32(len(e.Data)))
		binary.LittleEndian.PutUint16(lh[26:28], uint16(len(e.Name)))
		b = append(b, lh[:]...)
		b = append(b, e.Name...)
		b = append(b, e.Data...)
	}
	cdStart := len(b)
	for i := range entries {
		e := &entries[i]
		var ch [46]byte
		binary.LittleEndian.PutUint32(ch[0:4], 0x02014b50)
		binary.LittleEndian.PutUint16(ch[6:8], 20)
		binary.LittleEndian.PutUint32(ch[16:20], crc32.ChecksumIEEE(e.Data))
		binary.LittleEndian.PutUint32(ch[20:24], uint32(len(e.Data)))
		binary.LittleEndian.PutUint32(ch[24:28], uint32(len(e.Data)))
		binary.LittleEndian.PutUint16(ch[28:30], uint16(len(e.Name)))
		binary.LittleEndian.PutUint32(ch[42:46], uint32(offsets[i]))
		b = append(b, ch[:]...)
		b = append(b, e.Name...)
	}
	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(len(entries)))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(len(entries)))
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(len(b)-cdStart))
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdStart))
	return append(b, eocd[:]...)
}

// flipStoredEntryByte returns a copy of the container with the byte at
// dataOffset within the named stored entry replaced via fn; both CRC-32
// fields are recomputed so the rejection lands in the semantic layer.
func flipStoredEntryByte(t *testing.T, container []byte, entry string, dataOffset int, fn func(byte) byte) []byte {
	t.Helper()
	lhOff, cdOff, found := findEntryOffsetsUnit(t, container, entry)
	if !found {
		t.Fatalf("entry %q not found", entry)
	}
	nameLen := int(binary.LittleEndian.Uint16(container[lhOff+26 : lhOff+28]))
	extraLen := int(binary.LittleEndian.Uint16(container[lhOff+28 : lhOff+30]))
	dataStart := lhOff + 30 + nameLen + extraLen
	dataLen := int(binary.LittleEndian.Uint32(container[lhOff+18 : lhOff+22]))
	if dataOffset < 0 || dataOffset >= dataLen {
		t.Fatalf("byte offset %d outside entry %q (len %d)", dataOffset, entry, dataLen)
	}
	b := append([]byte(nil), container...)
	b[dataStart+dataOffset] = fn(b[dataStart+dataOffset])
	crc := crc32.ChecksumIEEE(b[dataStart : dataStart+dataLen])
	binary.LittleEndian.PutUint32(b[lhOff+14:lhOff+18], crc)
	binary.LittleEndian.PutUint32(b[cdOff+16:cdOff+20], crc)
	return b
}

// findEntryOffsetsUnit walks the central directory and returns the local
// header offset and the central directory offset of the named entry.
func findEntryOffsetsUnit(t *testing.T, container []byte, name string) (lhOff, cdOff int, found bool) {
	t.Helper()
	const eocdSig = "PK\x05\x06"
	eocd := len(container) - 22
	if !bytes.Equal(container[eocd:eocd+4], []byte(eocdSig)) {
		t.Fatalf("EOCD signature not found")
	}
	cdStart := int(binary.LittleEndian.Uint32(container[eocd+16 : eocd+20]))
	for off := cdStart; off+46 <= len(container); {
		if !bytes.Equal(container[off:off+4], []byte("PK\x01\x02")) {
			break
		}
		nameLen := int(binary.LittleEndian.Uint16(container[off+28 : off+30]))
		extraLen := int(binary.LittleEndian.Uint16(container[off+30 : off+32]))
		commentLen := int(binary.LittleEndian.Uint16(container[off+32 : off+34]))
		if off+46+nameLen > len(container) {
			break
		}
		if string(container[off+46:off+46+nameLen]) == name {
			return int(binary.LittleEndian.Uint32(container[off+42 : off+46])), off, true
		}
		off += 46 + nameLen + extraLen + commentLen
	}
	return 0, 0, false
}
