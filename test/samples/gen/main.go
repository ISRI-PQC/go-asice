// Command gen regenerates the hermetic test fixtures under
// test/samples from this repo's own testutil PKI + asic packages:
// the ASiC-E containers, the extracted EID signature XML, and the
// canonicalized SignedInfo golden. Nothing is copied from any external
// project — every fixture byte is produced by this repo (see
// test/samples/README.md for provenance).
//
// Run from the repo root:
//
//	go run ./test/samples/gen
//
// Deterministic inputs: a fixed reference time (testutil rejects the
// wall clock); the PKI keys are fresh per run, so the generated
// fixtures are time-deterministic, not byte-deterministic — the tests
// pin self-consistency (digests/canonical bytes computed from the same
// generated artifacts), not absolute bytes.
package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/beevik/etree"
	"github.com/isri-pqc/xmlsig/canonicalizers"
	xcrypto "github.com/isri-pqc/xmlsig/crypto"
	"github.com/isri-pqc/xmlsig/etreeutils"
	"github.com/isri-pqc/xmlsig/spec"

	"github.com/isri-pqc/asice/asic"
	asiccrypto "github.com/isri-pqc/asice/asic/crypto"
	"github.com/isri-pqc/asice/testutil"
)

// fixedNow is the single reference time of the generated fixtures
// (PKI reference time, every SigningTime, the OCSP producedAt and the
// TST genTime) — the single-time-T pattern (ADR 0001 §6).
var fixedNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	outDir, err := outDir()
	if err != nil {
		return err
	}

	p, err := testutil.NewPKI(testutil.Options{Now: fixedNow})
	if err != nil {
		return fmt.Errorf("NewPKI: %w", err)
	}
	dm := xcrypto.NewStdXMLDigestModule()
	sm0, err := asiccrypto.NewStdSignerModule(p.Signer.PrivateKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("signer module: %w", err)
	}
	sm1, err := asiccrypto.NewStdSignerModule(p.Signer2.PrivateKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("signer2 module: %w", err)
	}

	single := []asic.Doc{{Name: "test.txt", MediaType: "application/octet-stream", Data: []byte("Test data")}}
	multi := append([]asic.Doc{{Name: "test.txt", MediaType: "application/octet-stream", Data: []byte("Test data")}},
		asic.Doc{Name: "notes.txt", MediaType: "text/plain", Data: []byte("notes")})

	// --- testEIDBES.bdoc: 1 file, 1 signature (S0), BES profile ---
	sigBES, err := asic.SignBES(0, sm0, dm, p.Signer.Certificate, single, fixedNow)
	if err != nil {
		return fmt.Errorf("SignBES (EID): %w", err)
	}
	container, err := writeContainer(single, sigBES)
	if err != nil {
		return fmt.Errorf("EID BES container: %w", err)
	}
	if err := writeFile(outDir, "testEIDBES.bdoc", container); err != nil {
		return err
	}
	if err := selfVerify(outDir, "testEIDBES.bdoc", p, asic.ProfileBES); err != nil {
		return err
	}

	// --- testMultipleFiles.bdoc: 2 files, 1 signature (S0), BES ---
	sigMF, err := asic.SignBES(0, sm0, dm, p.Signer.Certificate, multi, fixedNow)
	if err != nil {
		return fmt.Errorf("SignBES (multi-file): %w", err)
	}
	container, err = writeContainer(multi, sigMF)
	if err != nil {
		return fmt.Errorf("multi-file container: %w", err)
	}
	if err := writeFile(outDir, "testMultipleFiles.bdoc", container); err != nil {
		return err
	}
	if err := selfVerify(outDir, "testMultipleFiles.bdoc", p, asic.ProfileBES); err != nil {
		return err
	}

	// --- testMultipleSigners.bdoc: 1 file, 2 signatures (S0, S1), BES ---
	sig0, err := asic.SignBES(0, sm0, dm, p.Signer.Certificate, single, fixedNow)
	if err != nil {
		return fmt.Errorf("SignBES (S0): %w", err)
	}
	sig1, err := asic.SignBES(1, sm1, dm, p.Signer2.Certificate, single, fixedNow)
	if err != nil {
		return fmt.Errorf("SignBES (S1): %w", err)
	}
	container, err = writeContainer(single, sig0, sig1)
	if err != nil {
		return fmt.Errorf("multi-signer container: %w", err)
	}
	if err := writeFile(outDir, "testMultipleSigners.bdoc", container); err != nil {
		return err
	}
	if err := selfVerify(outDir, "testMultipleSigners.bdoc", p, asic.ProfileBES); err != nil {
		return err
	}

	// --- testEIDTS.bdoc: 1 file, 1 signature (S0) with embedded TST +
	// --- OCSP, TS profile (single time fixedNow everywhere).
	ocsp, err := p.OCSPResponse(fixedNow)
	if err != nil {
		return fmt.Errorf("OCSPResponse: %w", err)
	}
	sigTS, err := asic.SignTS(0, sm0, dm, p.Signer.Certificate, single, fixedNow, asic.TSData{
		TimeStamp: func(d []byte) ([]byte, error) {
			return p.TimeStampToken(d, testutil.TSTOptions{GenTime: fixedNow})
		},
		OCSPResponse: ocsp,
		Certificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	})
	if err != nil {
		return fmt.Errorf("SignTS: %w", err)
	}
	container, err = writeContainer(single, sigTS)
	if err != nil {
		return fmt.Errorf("TS container: %w", err)
	}
	if err := writeFile(outDir, "testEIDTS.bdoc", container); err != nil {
		return err
	}
	if err := selfVerifyTS(outDir, "testEIDTS.bdoc", p); err != nil {
		return err
	}

	// --- extracted goldens from the EID BES container ---
	sigXML, err := zipEntry(container, "META-INF/signatures0.xml")
	if err != nil {
		return fmt.Errorf("extract signatures0.xml: %w", err)
	}
	if err := writeFile(outDir, "signatures0EID.xml", sigXML); err != nil {
		return err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(sigXML); err != nil {
		return fmt.Errorf("parse signatures0EID.xml: %w", err)
	}
	si := doc.FindElement("//ds:SignedInfo")
	if si == nil {
		return fmt.Errorf("SignedInfo not found in signatures0EID.xml")
	}
	parentCtx, err := etreeutils.NSBuildParentContext(si)
	if err != nil {
		return fmt.Errorf("namespace context: %w", err)
	}
	canon, err := canonicalizers.CanonicalizeSignedInfo(si, spec.CanonicalXML11AlgorithmId, parentCtx)
	if err != nil {
		return fmt.Errorf("canonicalize SignedInfo: %w", err)
	}
	if err := writeFile(outDir, "canonicalSignedInfoEID", canon); err != nil {
		return err
	}
	return nil
}

// outDir resolves test/samples relative to this source file, so the
// generator writes to the same place no matter the working directory.
func outDir() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot resolve source directory")
	}
	return filepath.Join(filepath.Dir(thisFile), ".."), nil
}

func writeFile(dir, name string, data []byte) error {
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(dir, name), len(data))
	return nil
}

// writeContainer renders the container bytes with asic.WriteContainer.
func writeContainer(docs []asic.Doc, sigs ...[]byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := asic.WriteContainer(&buf, docs, sigs...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zipEntry extracts the raw stored data of the named ZIP entry.
func zipEntry(container []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("no entry %q", name)
}

// selfVerify runs asic.Verify (BES profile) over a generated container
// as a sanity check of the generator's own output.
func selfVerify(dir, name string, p *testutil.PKI, profile asic.Profile) error {
	opts := asic.VerifyOptions{
		Profile:          profile,
		RootsPEM:         p.Root.PEM,
		IntermediatesPEM: p.Issuer.PEM,
		DigestModule:     xcrypto.NewStdXMLDigestModule(),
		VerifierModule:   asiccrypto.NewStdVerifierModule(),
		ChainModule:      asiccrypto.NewStdCertificateChainModule(),
		OCSPModule:       asiccrypto.NewStdOCSPVerifierModule(),
	}
	report, err := asic.Verify(filepath.Join(dir, name), opts)
	if err != nil {
		return fmt.Errorf("self-verify %s: %w", name, err)
	}
	if !report.OK {
		return fmt.Errorf("self-verify %s: report not OK", name)
	}
	return nil
}

// selfVerifyTS runs asic.Verify (TS profile) over the generated TS
// container (TST verifier over the TSA cert, OCSP responder pool).
func selfVerifyTS(dir, name string, p *testutil.PKI) error {
	opts := asic.VerifyOptions{
		Profile:           asic.ProfileTS,
		RootsPEM:          p.Root.PEM,
		IntermediatesPEM:  p.Issuer.PEM,
		OCSPRespondersPEM: p.OCSPResponder.PEM,
		DigestModule:      xcrypto.NewStdXMLDigestModule(),
		VerifierModule:    asiccrypto.NewStdVerifierModule(),
		ChainModule:       asiccrypto.NewStdCertificateChainModule(),
		OCSPModule:        asiccrypto.NewStdOCSPVerifierModule(),
	}
	tstSigners, err := asic.ParsePEMCerts(p.TSA.PEM)
	if err != nil {
		return fmt.Errorf("TSA PEM: %w", err)
	}
	intermediates, err := asic.ParsePEMCerts(p.Issuer.PEM)
	if err != nil {
		return fmt.Errorf("Issuer PEM: %w", err)
	}
	opts.TSTVerifier = asiccrypto.NewStdTSTVerifierModule(tstSigners, intermediates)
	report, err := asic.Verify(filepath.Join(dir, name), opts)
	if err != nil {
		return fmt.Errorf("self-verify %s: %w", name, err)
	}
	if !report.OK {
		return fmt.Errorf("self-verify %s: report not OK", name)
	}
	return nil
}
