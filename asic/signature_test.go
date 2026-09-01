package asic

// TestSignBESStructure mirrors the Estonian e-voting collector's BES
// verification path against our rendered signature XML (PLAN.md §1.2
// strict shape): re-canonicalize
// SignedInfo and verify the signature, re-canonicalize SignedProperties and
// check its digest, check file digests, and assert every structural rule
// the collector's schema-driven parser enforces (reference order/type,
// Ids, no
// SignaturePolicyIdentifier, no Object attributes, DOF mime types, ...).
// The final acceptance bar (the collector's Open() itself) is the M3 e2e
// test.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/isri-pqc/asice/testutil"
	"github.com/isri-pqc/asice/xades"
)

// TestSignBESIndex pins the S{k} identifier scheme of SignBES (Task 5):
// the k-th call must carry consistently indexed ds:Signature Id, reference
// Ids, SignatureValue Id, SignedProperties Id, QualifyingProperties Target
// and DataObjectFormat ObjectReferences — so repeated calls yield S0, S1,
// ... documents whose identifiers never collide, and the k=1 document is
// cryptographically sound (signature verifies over canonical SignedInfo,
// SP reference digest matches canonical SignedProperties).
func TestSignBESIndex(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	p, err := testutil.NewPKI(testutil.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	docs := []Doc{
		{Name: "f1.txt", MediaType: "application/octet-stream", Data: []byte("one")},
		{Name: "f2.txt", MediaType: "application/octet-stream", Data: []byte("two")},
	}
	// A negative index must be rejected.
	if _, err := SignBES(-1, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, now); err == nil {
		t.Fatal("SignBES(-1, ...) must fail")
	}

	for k, wantIDs := range map[int]struct {
		sig, sv, sp, target string
		refIds              []string
	}{
		0: {"S0", "S0-SIG", "S0-SignedProperties", "#S0", []string{"S0-RefId0", "S0-RefId1", "S0-RefId2"}},
		1: {"S1", "S1-SIG", "S1-SignedProperties", "#S1", []string{"S1-RefId0", "S1-RefId1", "S1-RefId2"}},
		3: {"S3", "S3-SIG", "S3-SignedProperties", "#S3", []string{"S3-RefId0", "S3-RefId1", "S3-RefId2"}},
	} {
		xmlBytes, err := SignBES(k, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, now)
		if err != nil {
			t.Fatalf("SignBES(%d): %v", k, err)
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(xmlBytes); err != nil {
			t.Fatalf("parse k=%d: %v", k, err)
		}
		sig := doc.Root().FindElement("ds:Signature")
		if sig == nil || sig.SelectAttrValue("Id", "") != wantIDs.sig {
			t.Fatalf("k=%d: ds:Signature Id = %v, want %s", k, idOf(sig), wantIDs.sig)
		}
		si := sig.FindElement("ds:SignedInfo")
		refs := si.FindElements("ds:Reference")
		if len(refs) != len(wantIDs.refIds) {
			t.Fatalf("k=%d: references: got %d, want %d", k, len(refs), len(wantIDs.refIds))
		}
		for i, r := range refs {
			if got := r.SelectAttrValue("Id", ""); got != wantIDs.refIds[i] {
				t.Errorf("k=%d: ref %d Id = %q, want %q", k, i, got, wantIDs.refIds[i])
			}
		}
		if got := refs[len(refs)-1].SelectAttrValue("URI", ""); got != "#"+wantIDs.sp {
			t.Errorf("k=%d: SP ref URI = %q", k, got)
		}
		sv := sig.FindElement("ds:SignatureValue")
		if sv.SelectAttrValue("Id", "") != wantIDs.sv {
			t.Errorf("k=%d: SignatureValue Id = %q", k, sv.SelectAttrValue("Id", ""))
		}
		qp := sig.FindElement("//xades:QualifyingProperties")
		if qp.SelectAttrValue("Target", "") != wantIDs.target {
			t.Errorf("k=%d: QP Target = %q", k, qp.SelectAttrValue("Target", ""))
		}
		sp := qp.FindElement("xades:SignedProperties")
		if sp.SelectAttrValue("Id", "") != wantIDs.sp {
			t.Errorf("k=%d: SP Id = %q", k, sp.SelectAttrValue("Id", ""))
		}
		for i, dof := range sp.FindElements("//xades:DataObjectFormat") {
			if got := dof.SelectAttrValue("ObjectReference", ""); got != "#"+wantIDs.refIds[i] {
				t.Errorf("k=%d: DOF %d ObjectReference = %q", k, i, got)
			}
		}

		// Cryptographic soundness of the k-th document: the signature
		// verifies over the canonical SignedInfo and the SP reference
		// digest matches the canonical SignedProperties.
		sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sv.Text()))
		if err != nil {
			t.Fatalf("k=%d: SignatureValue base64: %v", k, err)
		}
		ecdsaKey, ok := p.Signer.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("testutil signer is not ECDSA")
		}
		if len(sigBytes) != 2*((ecdsaKey.Curve.Params().BitSize+7)/8) {
			t.Fatalf("k=%d: ECDSA signature value length: got %d", k, len(sigBytes))
		}
		der, err := reencodeECDSA(sigBytes)
		if err != nil {
			t.Fatalf("k=%d: re-encode r||s: %v", k, err)
		}
		canon := signedInfoCanon(t, xmlBytes)
		if err := p.Signer.Certificate.CheckSignature(x509.ECDSAWithSHA256, canon, der); err != nil {
			t.Fatalf("k=%d: signature does not verify over canonical SignedInfo: %v", k, err)
		}
		spCanon, err := canonicalizeElement(sp)
		if err != nil {
			t.Fatalf("k=%d: %v", k, err)
		}
		spWant := sha256.Sum256(spCanon)
		spRef := refs[len(refs)-1]
		if got := strings.TrimSpace(spRef.FindElement("ds:DigestValue").Text()); got != base64.StdEncoding.EncodeToString(spWant[:]) {
			t.Errorf("k=%d: SP digest mismatch", k)
		}
	}

	// Two consecutive calls with distinct k must produce documents whose
	// identifier sets are disjoint (no S0/S1 collision).
	s0, _ := SignBES(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, now)
	s1, _ := SignBES(1, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, now)
	if strings.Contains(string(s1), `Id="S0`) || strings.Contains(string(s0), `Id="S1`) {
		t.Error("signature documents must not mix S0/S1 identifiers")
	}
}

// idOf returns the Id attribute of el or "<nil>".
func idOf(el *etree.Element) string {
	if el == nil {
		return "<nil>"
	}
	return el.SelectAttrValue("Id", "")
}

// signedInfoCanon parses the rendered document and returns the canonical
// C14N 1.1 bytes of its ds:SignedInfo — the same path the signing flow
// uses (asic.sign → canonicalizeElement), so these tests verify the
// signature over the bytes the collector reconstructs.
func signedInfoCanon(t *testing.T, docXML []byte) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(docXML); err != nil {
		t.Fatalf("parse rendered signature: %v", err)
	}
	si := doc.FindElement("//ds:SignedInfo")
	if si == nil {
		t.Fatal("ds:SignedInfo not found in rendered signature")
	}
	canon, err := canonicalizeElement(si)
	if err != nil {
		t.Fatalf("canonicalize SignedInfo: %v", err)
	}
	return canon
}

// reencodeECDSA re-encodes a raw r||s signature value (the XML-DSig
// encoding, W3C XML Signature 1.1 section 6.4.3) to ASN.1 DER — the
// re-encoding the collector's verification performs.
func reencodeECDSA(signature []byte) ([]byte, error) {
	if len(signature)%2 != 0 || len(signature) < 2 {
		return nil, errSigTooShort
	}
	n := len(signature) / 2
	var r, s big.Int
	r.SetBytes(signature[:n])
	s.SetBytes(signature[n:])
	return asn1.Marshal(struct {
		R, S *big.Int
	}{&r, &s})
}

type errTooShort struct{}

func (errTooShort) Error() string { return "signature too short" }

var errSigTooShort = errTooShort{}

func TestSignBESStructure(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	p, err := testutil.NewPKI(testutil.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	docs := []Doc{
		{Name: "test.txt", MediaType: "application/octet-stream", Data: []byte("data one")},
		{Name: "doc2.bin", MediaType: "application/pdf", Data: []byte("data two")},
	}
	xmlBytes, err := SignBES(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, now)
	if err != nil {
		t.Fatalf("SignBES: %v", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("parse rendered signature: %v", err)
	}

	// --- root: asic:XAdESSignatures with exactly the three ns bindings ---
	root := doc.Root()
	if root.Tag != "XAdESSignatures" || root.SelectAttrValue("xmlns:asic", "") != xades.NSASIC {
		t.Errorf("root element: %q (ns %q)", root.Tag, root.Space)
	}

	sig := root.FindElement("ds:Signature")
	if sig == nil || sig.SelectAttrValue("Id", "") != "S0" {
		t.Fatalf("ds:Signature Id=S0 not found")
	}

	// --- SignedInfo: algorithms + references (files FIRST, SP last) ---
	si := sig.FindElement("ds:SignedInfo")
	if si.SelectAttrValue("Id", "") != "" {
		t.Errorf("SignedInfo must not carry an Id attribute")
	}
	cm := si.FindElement("ds:CanonicalizationMethod")
	if cm.SelectAttrValue("Algorithm", "") != algC14N11 {
		t.Errorf("CanonicalizationMethod: %q", cm.SelectAttrValue("Algorithm", ""))
	}
	sm := si.FindElement("ds:SignatureMethod")
	if sm.SelectAttrValue("Algorithm", "") != algECDSASHA256 {
		t.Errorf("SignatureMethod: %q", sm.SelectAttrValue("Algorithm", ""))
	}

	refs := si.FindElements("ds:Reference")
	if len(refs) != len(docs)+1 {
		t.Fatalf("references: got %d, want %d", len(refs), len(docs)+1)
	}
	for i, d := range docs {
		r := refs[i]
		if r.SelectAttrValue("Id", "") != "S0-RefId"+strconv.Itoa(i) {
			t.Errorf("ref %d Id: %q", i, r.SelectAttrValue("Id", ""))
		}
		if r.SelectAttrValue("URI", "") != d.Name {
			t.Errorf("ref %d URI: %q", i, r.SelectAttrValue("URI", ""))
		}
		if r.SelectAttrValue("Type", "") != "" {
			t.Errorf("file ref %d must not have Type", i)
		}
		if tr := r.FindElement("ds:Transforms"); tr != nil {
			t.Errorf("file ref %d must not have Transforms", i)
		}
		if dm := r.FindElement("ds:DigestMethod"); dm.SelectAttrValue("Algorithm", "") != xades.DigestMethodSHA256 {
			t.Errorf("file ref %d DigestMethod: %q", i, dm.SelectAttrValue("Algorithm", ""))
		}
		want := sha256.Sum256(d.Data)
		if dv := r.FindElement("ds:DigestValue"); strings.TrimSpace(dv.Text()) != base64.StdEncoding.EncodeToString(want[:]) {
			t.Errorf("file ref %d digest mismatch", i)
		}
	}
	spRef := refs[len(docs)]
	if spRef.SelectAttrValue("Id", "") != "S0-RefId"+strconv.Itoa(len(docs)) {
		t.Errorf("SP ref Id: %q", spRef.SelectAttrValue("Id", ""))
	}
	if spRef.SelectAttrValue("URI", "") != "#S0-SignedProperties" {
		t.Errorf("SP ref URI: %q", spRef.SelectAttrValue("URI", ""))
	}
	if spRef.SelectAttrValue("Type", "") != xades.SignedPropertiesRefType {
		t.Errorf("SP ref Type: %q", spRef.SelectAttrValue("Type", ""))
	}

	// --- SignatureValue: Id + valid ECDSA r||s verifying over canonical SignedInfo ---
	sv := sig.FindElement("ds:SignatureValue")
	if sv.SelectAttrValue("Id", "") != "S0-SIG" {
		t.Errorf("SignatureValue Id: %q", sv.SelectAttrValue("Id", ""))
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sv.Text()))
	if err != nil {
		t.Fatalf("SignatureValue base64: %v", err)
	}
	ecdsaKey, ok := p.Signer.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("testutil signer is not ECDSA")
	}
	if len(sigBytes) != 2*((ecdsaKey.Curve.Params().BitSize+7)/8) {
		t.Fatalf("ECDSA signature value length: got %d, want %d (raw r||s)", len(sigBytes), (ecdsaKey.Curve.Params().BitSize+7)/2)
	}
	der, err := reencodeECDSA(sigBytes)
	if err != nil {
		t.Fatalf("re-encode r||s: %v", err)
	}
	canon := signedInfoCanon(t, xmlBytes)
	if err := p.Signer.Certificate.CheckSignature(x509.ECDSAWithSHA256, canon, der); err != nil {
		t.Fatalf("signature does not verify over canonical SignedInfo: %v", err)
	}

	// --- KeyInfo: exactly one X509Certificate, base64 == cert DER ---
	ki := sig.FindElement("ds:KeyInfo")
	certs := ki.FindElements("ds:X509Data/ds:X509Certificate")
	if len(certs) != 1 {
		t.Fatalf("X509Certificate count: got %d, want 1", len(certs))
	}
	certB64, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certs[0].Text()))
	if err != nil || string(certB64) != string(p.Signer.Certificate.Raw) {
		t.Errorf("KeyInfo certificate does not match signer cert DER")
	}

	// --- ds:Object: no attributes at all; QP Target; SP Id ---
	obj := sig.FindElement("ds:Object")
	if len(obj.Attr) != 0 {
		var attrs []string
		for _, a := range obj.Attr {
			attrs = append(attrs, a.Key)
		}
		t.Errorf("ds:Object must have no attributes, got %v", attrs)
	}
	qp := obj.FindElement("xades:QualifyingProperties")
	if qp == nil || qp.SelectAttrValue("Target", "") != "#S0" {
		t.Fatalf("QualifyingProperties Target: %q", qp.SelectAttrValue("Target", ""))
	}
	sp := qp.FindElement("xades:SignedProperties")
	if sp.SelectAttrValue("Id", "") != "S0-SignedProperties" {
		t.Errorf("SignedProperties Id: %q", sp.SelectAttrValue("Id", ""))
	}
	if usp := qp.FindElement("xades:UnsignedProperties"); usp != nil {
		t.Errorf("BES signature must not carry UnsignedProperties")
	}

	// --- SignedSignatureProperties: time, SigningCertificate, NO policy ---
	ssp := sp.FindElement("xades:SignedSignatureProperties")
	st := ssp.FindElement("xades:SigningTime")
	if st.Text() != now.Format(time.RFC3339) {
		t.Errorf("SigningTime: %q", st.Text())
	}
	if spi := ssp.FindElement("xades:SignaturePolicyIdentifier"); spi != nil {
		t.Error("SignaturePolicyIdentifier must be absent")
	}
	cd := ssp.FindElement("xades:SigningCertificate/xades:Cert/xades:CertDigest")
	if dm := cd.FindElement("ds:DigestMethod"); dm.SelectAttrValue("Algorithm", "") != xades.DigestMethodSHA256 {
		t.Errorf("CertDigest DigestMethod: %q", dm.SelectAttrValue("Algorithm", ""))
	}
	cdWant := sha256.Sum256(p.Signer.Certificate.Raw)
	if strings.TrimSpace(cd.FindElement("ds:DigestValue").Text()) != base64.StdEncoding.EncodeToString(cdWant[:]) {
		t.Error("CertDigest value mismatch (KeyInfo cert digest)")
	}
	serialEl := ssp.FindElement("xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")
	if serialEl.Text() != p.Signer.Certificate.SerialNumber.String() {
		t.Errorf("X509SerialNumber: got %q, want %q", serialEl.Text(), p.Signer.Certificate.SerialNumber.String())
	}
	issuerEl := ssp.FindElement("xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
	if issuerEl.Text() != xades.IssuerName(p.Signer.Certificate) {
		t.Errorf("X509IssuerName: got %q", issuerEl.Text())
	}

	// --- SignedDataObjectProperties: one DOF per file, MimeType only ---
	dops := sp.FindElement("xades:SignedDataObjectProperties")
	dofs := dops.FindElements("xades:DataObjectFormat")
	if len(dofs) != len(docs) {
		t.Fatalf("DataObjectFormat count: got %d, want %d", len(dofs), len(docs))
	}
	for i, d := range docs {
		dof := dofs[i]
		if dof.SelectAttrValue("ObjectReference", "") != "#S0-RefId"+strconv.Itoa(i) {
			t.Errorf("DOF %d ObjectReference: %q", i, dof.SelectAttrValue("ObjectReference", ""))
		}
		mt := dof.FindElement("xades:MimeType")
		if mt == nil || mt.Text() != d.MediaType {
			t.Errorf("DOF %d MimeType: %v", i, mt)
		}
		var elKids []*etree.Element
		for _, c := range dof.Child {
			if e, ok := c.(*etree.Element); ok {
				elKids = append(elKids, e)
			}
		}
		if len(elKids) != 1 || elKids[0].Tag != "MimeType" {
			t.Errorf("DOF %d must contain only MimeType, has %d element children", i, len(elKids))
		}
	}

	// --- SP digest: canonical bytes → SHA-256 == the SignedInfo reference ---
	spCanon, err := canonicalizeElement(sp)
	if err != nil {
		t.Fatal(err)
	}
	spWant := sha256.Sum256(spCanon)
	if got := strings.TrimSpace(spRef.FindElement("ds:DigestValue").Text()); got != base64.StdEncoding.EncodeToString(spWant[:]) {
		t.Errorf("SignedProperties digest:\n got %s\nwant %s\n(canonical %d bytes)",
			got, base64.StdEncoding.EncodeToString(spWant[:]), len(spCanon))
	}
}
