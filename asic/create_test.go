// Unit tests for the high-level Create orchestration (PLAN.md Task 9):
// BES and TS container creation over the hermetic testutil PKI, signer
// file parsing, and document loading. The BES containers are
// self-verified with asic.Verify; the TS containers are verified under
// the BES profile (a TS container is BES-valid — its UnsignedProperties
// are outside the BES check surface) and inspected for the embedded
// TST + OCSP. The interop acceptance gate for both profiles lives in
// the external acceptance harness (maintained outside this repo).
package asic

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	asiccrypto "github.com/isri-pqc/go-asice/asic/crypto"
	"github.com/isri-pqc/go-asice/testutil"
	"github.com/isri-pqc/go-xmlsig/spec"
)

// createT is the single reference time of the Create unit matrix.
var createT = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

func newCreatePKI(t *testing.T) *testutil.PKI {
	t.Helper()
	p, err := testutil.NewPKI(testutil.Options{Now: createT})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	return p
}

// signerPEM renders the signer file shape ParseSigner accepts: the
// certificate PEM block plus the private key as a PKCS#8 PEM block.
func signerPEM(t *testing.T, c *testutil.Cert) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return append(append([]byte{}, c.PEM...), key...)
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func zipEntryBytes(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open container zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatalf("%s not in container", name)
	return nil
}

// TestCreateBES: one file, one signer -> container that passes our
// BES self-verification.
func TestCreateBES(t *testing.T) {
	p := newCreatePKI(t)
	docs := []Doc{{Name: "test.txt", MediaType: "text/plain", Data: []byte("create bes data")}}
	s, err := ParseSigner(signerPEM(t, p.Signer))
	if err != nil {
		t.Fatalf("ParseSigner: %v", err)
	}

	var buf bytes.Buffer
	err = Create(&buf, CreateOptions{
		Docs:         docs,
		Signers:      []Signer{s},
		Profile:      ProfileBES,
		SigningTime:  createT,
		DigestModule: stdDigestModule(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cpath := writeTemp(t, "bes.asice", buf.Bytes())
	rep, err := Verify(cpath, besVerifyOptions(p.Root.PEM, p.Issuer.PEM))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("self-verify FAILED: %v", rep.Errors)
	}
	if len(rep.Signatures) != 1 || rep.Signatures[0].ID != "S0" {
		t.Fatalf("signatures: got %+v, want one S0", rep.Signatures)
	}
	if len(rep.DataFiles) != 1 || rep.DataFiles[0] != "test.txt" {
		t.Fatalf("data files: got %v, want [test.txt]", rep.DataFiles)
	}
}

// TestCreateBESMultiSigner: two signers -> S0 + S1, both verified.
func TestCreateBESMultiSigner(t *testing.T) {
	p := newCreatePKI(t)
	docs := []Doc{{Name: "a.txt", MediaType: "text/plain", Data: []byte("multi")},
		{Name: "b.txt", MediaType: "application/octet-stream", Data: []byte("multi 2")}}
	s0, err := ParseSigner(signerPEM(t, p.Signer))
	if err != nil {
		t.Fatal(err)
	}
	s1, err := ParseSigner(signerPEM(t, p.Signer2))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, CreateOptions{
		Docs:         docs,
		Signers:      []Signer{s0, s1},
		Profile:      ProfileBES,
		SigningTime:  createT,
		DigestModule: stdDigestModule(),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	cpath := writeTemp(t, "multi.asice", buf.Bytes())
	rep, err := Verify(cpath, besVerifyOptions(p.Root.PEM, p.Issuer.PEM))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("self-verify FAILED: %v", rep.Errors)
	}
	if len(rep.Signatures) != 2 || rep.Signatures[0].ID != "S0" || rep.Signatures[1].ID != "S1" {
		t.Fatalf("signature IDs: got %v", idsOf(rep))
	}
}

// TestCreateTS: TS-profile creation with a hermetic TST callback ->
// container that passes BES self-verification and carries the embedded
// TST + OCSP (the TS interop acceptance gate itself lives in the
// external acceptance harness, maintained outside this repo).
func TestCreateTS(t *testing.T) {
	p := newCreatePKI(t)
	docs := []Doc{{Name: "test.txt", MediaType: "text/plain", Data: []byte("create ts data")}}
	s, err := ParseSigner(signerPEM(t, p.Signer))
	if err != nil {
		t.Fatal(err)
	}
	ocsp, err := p.OCSPResponse(createT)
	if err != nil {
		t.Fatalf("OCSPResponse: %v", err)
	}

	var buf bytes.Buffer
	err = Create(&buf, CreateOptions{
		Docs:         docs,
		Signers:      []Signer{s},
		Profile:      ProfileTS,
		SigningTime:  createT,
		DigestModule: stdDigestModule(),
		TimeStamp: func(data []byte) ([]byte, error) {
			return p.TimeStampToken(data, testutil.TSTOptions{GenTime: createT})
		},
		// The hermetic TST carries no TSDelayTime policy parameter; the
		// explicit bound feeds the create-time guard.
		TSDelay:        60 * time.Second,
		OCSPResponse:   ocsp,
		TSCertificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sig := zipEntryBytes(t, buf.Bytes(), "META-INF/signatures0.xml")
	if !strings.Contains(string(sig), "EncapsulatedTimeStamp") {
		t.Error("TS signature lacks the embedded TST (EncapsulatedTimeStamp)")
	}
	if !strings.Contains(string(sig), "EncapsulatedOCSPValue") {
		t.Error("TS signature lacks the embedded OCSP (EncapsulatedOCSPValue)")
	}

	cpath := writeTemp(t, "ts.asice", buf.Bytes())
	rep, err := Verify(cpath, besVerifyOptions(p.Root.PEM, p.Issuer.PEM))
	if err != nil {
		t.Fatalf("Verify (BES view of a TS container): %v", err)
	}
	if !rep.OK {
		t.Fatalf("self-verify FAILED: %v", rep.Errors)
	}
}

// --- create-time TSDelayTime guard (the same predicate verify applies) ---

// tsGuardPKI builds the TS-profile Create options skeleton for the
// TSDelayTime guard tests: hermetic PKI, one document, standard
// modules, the TST at genTime (with the optional policy bound).
func newTSTSGuardFixture(t *testing.T) (*testutil.PKI, []Doc, Signer, []byte) {
	t.Helper()
	p := newCreatePKI(t)
	docs := []Doc{{Name: "test.txt", MediaType: "text/plain", Data: []byte("guard data")}}
	s, err := ParseSigner(signerPEM(t, p.Signer))
	if err != nil {
		t.Fatal(err)
	}
	ocsp, err := p.OCSPResponse(createT) // producedAt = createT
	if err != nil {
		t.Fatal(err)
	}
	return p, docs, s, ocsp
}

func tsGuardTST(p *testutil.PKI, genTime time.Time, policyBound time.Duration) func(data []byte) ([]byte, error) {
	opts := testutil.TSTOptions{GenTime: genTime}
	if policyBound > 0 {
		policy := asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
		secs, err := asn1.Marshal(int(policyBound.Seconds()))
		if err != nil {
			panic(err)
		}
		opts.Policy = policy
		opts.Extensions = []pkix.Extension{{Id: policy, Value: secs}}
	}
	return func(data []byte) ([]byte, error) {
		return p.TimeStampToken(data, opts)
	}
}

func tsGuardVerifyOptions(t *testing.T, p *testutil.PKI) VerifyOptions {
	t.Helper()
	o := stdVerifyOptions(ProfileTS)
	o.RootsPEM = p.Root.PEM
	o.IntermediatesPEM = p.Issuer.PEM
	o.OCSPRespondersPEM = p.OCSPResponder.PEM
	tstSigners, err := ParsePEMCerts(p.TSA.PEM)
	if err != nil {
		t.Fatal(err)
	}
	o.TSTVerifier = asiccrypto.NewStdTSTVerifierModule(tstSigners, []*x509.Certificate{p.Issuer.Certificate})
	return o
}

// TestCreateTSTSDelayWithinBound: the create-time guard passes when the
// stored OCSP producedAt is inside the bound of the TST genTime. The
// bound comes from the TST's TSA policy (no explicit TSDelay), and the
// container self-verifies under the TS profile.
func TestCreateTSTSDelayWithinBound(t *testing.T) {
	p, docs, s, ocsp := newTSTSGuardFixture(t)
	var buf bytes.Buffer
	err := Create(&buf, CreateOptions{
		Docs:           docs,
		Signers:        []Signer{s},
		Profile:        ProfileTS,
		SigningTime:    createT,
		DigestModule:   stdDigestModule(),
		TimeStamp:      tsGuardTST(p, createT, 60*time.Second), // genTime == producedAt: gap 0
		OCSPResponse:   ocsp,
		TSCertificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	})
	if err != nil {
		t.Fatalf("Create: %v (want success inside the bound)", err)
	}
	rep, err := Verify(writeTemp(t, "ts.asice", buf.Bytes()), tsGuardVerifyOptions(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("self-verify FAILED: %v / %v", rep.Errors, sigErrors(rep))
	}
}

// TestCreateTSTSDelayStaleOCSP: a stale stored OCSP (producedAt OUTSIDE
// the bound of the TST genTime) fails create with the stable, greppable
// TSDelayTime message and no container is written. Both bound sources
// are covered: the TST policy and the explicit TSDelay.
func TestCreateTSTSDelayStaleOCSP(t *testing.T) {
	p, docs, s, ocsp := newTSTSGuardFixture(t)
	// genTime = createT + 5 min, producedAt = createT: the gap is
	// -5 min, outside [0, bound].
	cases := []struct {
		name     string
		tsDelay  time.Duration // 0: the policy bound
		policyOK bool
	}{
		{"policy bound", 0, true},
		{"explicit bound", 60 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Create(&buf, CreateOptions{
				Docs:           docs,
				Signers:        []Signer{s},
				Profile:        ProfileTS,
				SigningTime:    createT,
				DigestModule:   stdDigestModule(),
				TimeStamp:      tsGuardTST(p, createT.Add(5*time.Minute), 60*time.Second),
				TSDelay:        tc.tsDelay,
				OCSPResponse:   ocsp,
				TSCertificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
			})
			if err == nil {
				t.Fatal("Create succeeded, want the TSDelayTime failure")
			}
			msg := err.Error()
			for _, want := range []string{"TSDelayTime", "OCSP producedAt", "TST genTime", "the TSDelayTime bound is"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q lacks %q", msg, want)
				}
			}
			if buf.Len() != 0 {
				t.Error("container written despite the TSDelayTime failure")
			}
		})
	}
}

// TestCreateTSDelaySharedWithVerify: the same violating pairing that the
// create-time guard rejects fails at verify time with the same message —
// one predicate (tsDelayOK), one verdict.
func TestCreateTSDelaySharedWithVerify(t *testing.T) {
	p, docs, s, ocsp := newTSTSGuardFixture(t)
	// Build the violating container directly over the primitives
	// (bypassing the create-time guard).
	sig, err := SignTS(0, s.SignerModule, stdDigestModule(), s.Certificate, docs, createT, TSData{
		TimeStamp:    tsGuardTST(p, createT.Add(5*time.Minute), 60*time.Second),
		OCSPResponse: ocsp,
		Certificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteContainer(&buf, docs, sig); err != nil {
		t.Fatal(err)
	}
	o := tsGuardVerifyOptions(t, p)
	o.TSDelayTime = 60 * time.Second
	expectFail(t, writeTemp(t, "ts.asice", buf.Bytes()), o, "the TSDelayTime bound is")
}

// TestCreateTSTSDelayNoBound: no explicit TSDelay and a TST without the
// policy parameter -> the actionable no-bound failure, before the
// container is written (predict verify, fail early).
func TestCreateTSTSDelayNoBound(t *testing.T) {
	p, docs, s, ocsp := newTSTSGuardFixture(t)
	var buf bytes.Buffer
	err := Create(&buf, CreateOptions{
		Docs:           docs,
		Signers:        []Signer{s},
		Profile:        ProfileTS,
		SigningTime:    createT,
		DigestModule:   stdDigestModule(),
		TimeStamp:      tsGuardTST(p, createT, 0), // no policy bound
		OCSPResponse:   ocsp,
		TSCertificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	})
	if err == nil || !strings.Contains(err.Error(), "no TSDelayTime bound") {
		t.Fatalf("Create error = %v, want the no TSDelayTime bound failure", err)
	}
	if buf.Len() != 0 {
		t.Error("container written despite the no-bound failure")
	}
}

// TestCreateValidation pins the option contract errors.
func TestCreateValidation(t *testing.T) {
	p := newCreatePKI(t)
	doc := []Doc{{Name: "a.txt", MediaType: "text/plain", Data: []byte("x")}}
	dm := stdDigestModule()
	s := Signer{Certificate: p.Signer.Certificate, SignerModule: stdSignerModule(t, p.Signer.PrivateKey)}

	cases := []struct {
		name string
		opts CreateOptions
		want string
	}{
		{"no docs", CreateOptions{Signers: []Signer{s}, SigningTime: createT, DigestModule: dm}, "data file"},
		{"no signers", CreateOptions{Docs: doc, SigningTime: createT, DigestModule: dm}, "signer"},
		{"no digest module", CreateOptions{Docs: doc, Signers: []Signer{s}}, "digest module"},
		{"zero time", CreateOptions{Docs: doc, Signers: []Signer{s}, DigestModule: dm}, "SigningTime"},
		{"unknown profile", CreateOptions{Docs: doc, Signers: []Signer{s}, Profile: Profile(7), SigningTime: createT, DigestModule: dm}, "profile"},
		{"ts no timestamp", CreateOptions{Docs: doc, Signers: []Signer{s}, Profile: ProfileTS, SigningTime: createT, DigestModule: dm}, "TimeStamp"},
		{"ts no ocsp", CreateOptions{Docs: doc, Signers: []Signer{s}, Profile: ProfileTS, SigningTime: createT, DigestModule: dm,
			TimeStamp: func([]byte) ([]byte, error) { return nil, nil }}, "OCSP"},
		{"ts wrong cert count", CreateOptions{Docs: doc, Signers: []Signer{s}, Profile: ProfileTS, SigningTime: createT, DigestModule: dm,
			TimeStamp: func([]byte) ([]byte, error) { return nil, nil }, OCSPResponse: []byte("ocsp"),
			TSCertificates: []*x509.Certificate{p.Issuer.Certificate}}, "TSCertificates"},
		{"incomplete signer", CreateOptions{Docs: doc, Signers: []Signer{{Certificate: s.Certificate}}, SigningTime: createT, DigestModule: dm}, "incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Create(&buf, tc.opts)
			if err == nil {
				t.Fatalf("Create succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestParseSigner covers the signer file contract.
func TestParseSigner(t *testing.T) {
	p := newCreatePKI(t)

	t.Run("valid", func(t *testing.T) {
		s, err := ParseSigner(signerPEM(t, p.Signer))
		if err != nil {
			t.Fatalf("ParseSigner: %v", err)
		}
		if s.Certificate.SerialNumber.Cmp(p.Signer.Certificate.SerialNumber) != 0 {
			t.Errorf("certificate mismatch")
		}
		if s.SignerModule == nil {
			t.Fatal("signer module missing")
		}
		alg, algErr := s.SignerModule.GetXMLSignatureAlgorithmID()
		if algErr != nil || alg != spec.ECDSASHA256SignatureMethod {
			t.Errorf("signer algorithm %q (err %v), want ECDSA-SHA256", alg, algErr)
		}
	})

	t.Run("certificate only", func(t *testing.T) {
		if _, err := ParseSigner(p.Signer.PEM); err == nil || !strings.Contains(err.Error(), "private key") {
			t.Fatalf("error = %v, want a private-key complaint", err)
		}
	})

	t.Run("key only", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(p.Signer.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, err := ParseSigner(key); err == nil || !strings.Contains(err.Error(), "CERTIFICATE") {
			t.Fatalf("error = %v, want a certificate complaint", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := ParseSigner([]byte("not a pem")); err == nil || !strings.Contains(err.Error(), "CERTIFICATE") {
			t.Fatalf("error = %v, want a certificate complaint", err)
		}
	})

	t.Run("two certificates", func(t *testing.T) {
		both := append(append([]byte{}, p.Signer.PEM...), p.Signer.PEM...)
		if _, err := ParseSigner(both); err == nil || !strings.Contains(err.Error(), "more than one") {
			t.Fatalf("error = %v, want a duplicate-certificate complaint", err)
		}
	})

	t.Run("corrupt key", func(t *testing.T) {
		bad := append(append([]byte{}, p.Signer.PEM...),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02}})...)
		if _, err := ParseSigner(bad); err == nil || !strings.Contains(err.Error(), "private key") {
			t.Fatalf("error = %v, want a private-key complaint", err)
		}
	})
}

// TestParsePrivateKey covers the key decodings (PEM + DER).
func TestParsePrivateKey(t *testing.T) {
	p := newCreatePKI(t)
	der, err := x509.MarshalPKCS8PrivateKey(p.Signer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if _, err := ParsePrivateKey(pemKey); err != nil {
		t.Errorf("PEM PKCS#8: %v", err)
	}
	if _, err := ParsePrivateKey(der); err != nil {
		t.Errorf("DER PKCS#8: %v", err)
	}
	if _, err := ParsePrivateKey([]byte("garbage")); err == nil {
		t.Errorf("garbage parsed, want error")
	}
}

// TestDocsFromPaths covers the loader (base name, media type, content)
// and the missing-file error.
func TestDocsFromPaths(t *testing.T) {
	dir := t.TempDir()
	pdf := filepath.Join(dir, "a.pdf")
	txt := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(pdf, []byte("pdf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(txt, []byte("txt"), 0o644); err != nil {
		t.Fatal(err)
	}

	docs, err := DocsFromPaths([]string{pdf, txt})
	if err != nil {
		t.Fatalf("DocsFromPaths: %v", err)
	}
	want := []struct{ name, media string }{
		{"a.pdf", "application/pdf"},
		{"b.txt", "text/plain"},
	}
	for i := range docs {
		if docs[i].Name != want[i].name || docs[i].MediaType != want[i].media {
			t.Errorf("doc %d: got (%s, %s), want (%s, %s)", i, docs[i].Name, docs[i].MediaType, want[i].name, want[i].media)
		}
	}
	if !bytes.Equal(docs[0].Data, []byte("pdf")) {
		t.Errorf("content not read")
	}

	if _, err := DocsFromPaths([]string{filepath.Join(dir, "missing.bin")}); err == nil {
		t.Errorf("missing file: want error")
	}
	if _, err := DocsFromPaths(nil); err == nil {
		t.Errorf("no files: want error")
	}
}

func TestMediaTypeForName(t *testing.T) {
	cases := map[string]string{
		"a.txt": "text/plain", "a.pdf": "application/pdf", "a.xml": "application/xml",
		"a.json": "application/json", "a.csv": "text/csv", "a.html": "text/html",
		"a.png": "image/png", "a.jpg": "image/jpeg", "a.bin": "application/octet-stream",
		"a": "application/octet-stream", "a.TXT": "text/plain",
	}
	for name, want := range cases {
		if got := MediaTypeForName(name); got != want {
			t.Errorf("%s: got %s, want %s", name, got, want)
		}
	}
}

func idsOf(rep *Report) []string {
	out := make([]string, len(rep.Signatures))
	for i, s := range rep.Signatures {
		out[i] = s.ID
	}
	return out
}
