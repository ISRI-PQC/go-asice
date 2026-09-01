package asic

import (
	"bytes"
	"strings"
	"testing"
)

// rewrap verifies a container whose signature doc has been replaced by
// mutatedSig (all data files unchanged), returning the report.
func (h *verifyHarness) rewrap(t *testing.T, mutatedSig []byte) *Report {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteContainer(&buf, h.docs, mutatedSig); err != nil {
		t.Fatalf("rewrap WriteContainer: %v", err)
	}
	rep, err := Verify(h.path(t, buf.Bytes()), h.opts())
	if err != nil {
		t.Fatalf("rewrap Verify: %v", err)
	}
	return rep
}

func (h *verifyHarness) mutate(t *testing.T, old, new string) []byte {
	t.Helper()
	sig := string(h.sig)
	if !strings.Contains(sig, old) {
		t.Fatalf("mutation marker %q not found", old)
	}
	return []byte(strings.Replace(sig, old, new, 1))
}

// The SP reference URI is a position-independent shorthand pointer
// ("#S0-SignedProperties"). The IBM paper (RC23691) warns that a naive
// verifier dereferences such pointers by searching for the matching Id
// anywhere in the document, letting an attacker move or duplicate the
// signed element and redirect verification. These tests probe whether
// go-asice's verifier dereferences by Id (vulnerable) or anchors on the
// fixed document structure (secure).
func TestAudit_SPDerefIsStructural(t *testing.T) {
	h := newVerifyHarness(t)

	// Decoy SP carrying the SAME Id as the real one but a wildly
	// different SigningTime, inserted right after <ds:Object> — i.e.
	// BEFORE the real SP in document order. A naive "first element with
	// this Id" dereference would pick up the decoy and report 2099.
	decoy := `<xades:SignedProperties Id="S0-SignedProperties"><xades:SignedSignatureProperties><xades:SigningTime>2099-01-01T00:00:00Z</xades:SigningTime></xades:SignedSignatureProperties></xades:SignedProperties>`
	rep := h.rewrap(t, h.mutate(t, `<ds:Object>`, `<ds:Object>`+decoy))

	// The decoy must have NO effect: the container still verifies the
	// REAL SP (structural anchor = the QP's direct child), so the
	// report's SigningTime is the real verifyT, not the decoy's 2099.
	if !rep.OK {
		t.Fatalf("decoy SP with same Id unexpectedly rejected (got %v); if this PASSes the decoy is being ignored correctly", rep.Errors)
	}
	if got := rep.Signatures[0].SigningTime; !got.Equal(verifyT) {
		t.Fatalf("verifier followed the decoy's Id: SigningTime=%v, want real %v (position-independent Id dereference!)", got, verifyT)
	}
}

// Wrapping the real SP in an extra element removes it from the QP's
// direct children. The verifier must reject it (structural anchor), not
// still find it by Id.
func TestAudit_WrapSP(t *testing.T) {
	h := newVerifyHarness(t)
	rep := h.rewrap(t, h.mutate(t,
		`<xades:SignedProperties Id="S0-SignedProperties">`,
		`<xades:W><xades:SignedProperties Id="S0-SignedProperties">`))
	rep2 := h.rewrap(t, h.mutate(t,
		`</xades:SignedProperties></xades:QualifyingProperties>`,
		`</xades:SignedProperties></xades:W></xades:QualifyingProperties>`))
	_ = rep
	// Both mutations must be rejected: the SP is no longer a direct
	// child of the QP, so the structural anchor finds 0 SP elements.
	for i, r := range []*Report{rep, rep2} {
		if r.OK {
			t.Fatalf("wrapped SP (variant %d) was ACCEPTED — wrapping attack works", i)
		}
	}
}

// A second xades:SignedProperties directly under the QP must be
// rejected by the "exactly one" structural check.
func TestAudit_SecondSPUnderQP(t *testing.T) {
	h := newVerifyHarness(t)
	second := `<xades:SignedProperties Id="S0-SignedProperties-B"><xades:SignedSignatureProperties><xades:SigningTime>2099-01-01T00:00:00Z</xades:SigningTime></xades:SignedSignatureProperties></xades:SignedProperties>`
	rep := h.rewrap(t, h.mutate(t,
		`</xades:SignedProperties></xades:QualifyingProperties>`,
		`</xades:SignedProperties>`+second+`</xades:QualifyingProperties>`))
	if rep.OK {
		t.Fatalf("a second SP under the QP was ACCEPTED (got %v)", rep.Errors)
	}
}

// Gutmann's "sign the wrong node / swap the content" (Brad Hill):
// re-pointing a reference at a different resource must be blocked by the
// SignedInfo signature (the reference's URI is inside the signed region).
func TestAudit_SwapFileReference(t *testing.T) {
	h := newVerifyHarness(t)
	rep := h.rewrap(t, h.mutate(t, `URI="test.txt"`, `URI="attacker.txt"`))
	if rep.OK {
		t.Fatalf("re-pointing the file reference to attacker.txt was ACCEPTED — Brad-Hill swap works")
	}
	// It must fail because the SignedInfo (which contains the reference
	// URI) no longer matches the SignatureValue.
	if !containsAny(rep.Signatures[0].Errors, "signature verification failed") {
		t.Errorf("expected a SignedInfo signature failure, got: %v", rep.Signatures[0].Errors)
	}
}

// Wrapping the whole ds:Signature in an extra element must be rejected
// (the document root must contain exactly one element, a ds:Signature).
func TestAudit_WrapSignature(t *testing.T) {
	h := newVerifyHarness(t)
	rep := h.rewrap(t, h.mutate(t,
		`<ds:Signature Id="S0">`,
		`<xades:W><ds:Signature Id="S0">`))
	// close the wrapper at the very end of the doc
	rep = h.rewrap(t, h.mutate(t,
		`</ds:Signature></asic:XAdESSignatures>`,
		`</ds:Signature></xades:W></asic:XAdESSignatures>`))
	if rep.OK {
		t.Fatalf("wrapping the whole ds:Signature was ACCEPTED — wrapper attack works")
	}
}

func containsAny(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
