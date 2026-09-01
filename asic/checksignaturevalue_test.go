// checkSignatureValue error-path test (ADR 0004): a SignatureValue
// whose text is not valid base64 must record the failure and stop —
// the pluggable verifier module must never be invoked with a nil
// signature value on hostile input (a custom backend may panic on
// nil: crash/DoS via a malicious container).

package asic

import (
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/isri-pqc/go-xmlsig/spec"

	"github.com/isri-pqc/asice/testutil"
	"github.com/isri-pqc/asice/xades"
)

// recordingVerifier is a mock XMLSignatureVerifierModule (ADR 0004):
// it records every VerifySignedInfo call and fails the test when one
// arrives with a nil signature.
type recordingVerifier struct {
	t       *testing.T
	calls   int
	lastSig []byte
}

// ValidateCertificate is the null implementation of the mock.
func (v *recordingVerifier) ValidateCertificate(cert []byte) error { return nil }

// VerifySignedInfo records the call and reports a nil signature.
func (v *recordingVerifier) VerifySignedInfo(signedInfo, cert, sig []byte, algoId spec.XMLSignatureAlgorithmID) error {
	v.calls++
	v.lastSig = sig
	if sig == nil {
		v.t.Errorf("VerifySignedInfo called with a nil signature")
	}
	return nil
}

func TestCheckSignatureValueInvalidBase64(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: verifyT})
	if err != nil {
		t.Fatal(err)
	}
	cert := p.Signer.Certificate

	verifier := &recordingVerifier{t: t}
	m := &verifyModules{verifier: verifier}

	// The minimal signature-document shape: ds:Signature holding one
	// ds:SignedInfo (the supported C14N 1.1 + RSA SHA-256 methods) and
	// a ds:SignatureValue with invalid base64.
	doc := etree.NewDocument()
	root := doc.CreateElement("asic:XAdESSignatures")
	root.CreateAttr("xmlns:asic", xades.NSASIC)
	root.CreateAttr("xmlns:ds", xades.NSDSIG)
	sig := root.CreateElement("ds:Signature")
	sig.CreateAttr("Id", "S0")
	si := sig.CreateElement("ds:SignedInfo")
	si.CreateElement("ds:CanonicalizationMethod").
		CreateAttr("Algorithm", algC14N11)
	si.CreateElement("ds:SignatureMethod").
		CreateAttr("Algorithm", string(spec.RSASHA256SignatureMethod))
	sv := sig.CreateElement("ds:SignatureValue")
	sv.SetText("not-base64!!")

	report := &SignatureReport{}
	fail := func(format string, args ...any) {
		report.Errors = append(report.Errors, fmt.Sprintf(format, args...))
	}
	checkSignatureValue(m, sv, si, cert, "signatures0.xml", fail)

	joined := strings.Join(report.Errors, "; ")
	if !strings.Contains(joined, "decode SignatureValue base64") {
		t.Errorf("errors %q: want the SignatureValue base64 decode failure", joined)
	}
	if got := finish(report).OK; got {
		t.Error("the report must be failed, got OK")
	}
	if verifier.calls != 0 {
		t.Errorf("VerifySignedInfo was called %d times, want 0 (nil signature must not reach the verifier)", verifier.calls)
	}
}
