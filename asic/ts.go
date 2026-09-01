// TS-profile signing (PLAN.md Task 7): signs the TS-profile XAdES
// signature document with xades:UnsignedProperties (TST + OCSP + embedded
// certificates) inside xades:QualifyingProperties, on top of the BES core
// built and signed by the SignBES machinery (signature.go).
//
// The asic package performs no TSA or OCSP I/O: SignTS takes the finished
// artifacts (TSData) and renders. The one exception is TSData.TimeStamp,
// a TST-producing callback: the TST's message imprint covers the C14N 1.1
// bytes of the document's ds:SignatureValue element, and those bytes only
// exist once the document is signed — so the token cannot be supplied up
// front. The Estonian e-voting collector's offline TST check (the
// timestamp-verification data path)
// verifies exactly that imprint.
package asic

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/isri-pqc/asice/xades"
	xcrypto "github.com/isri-pqc/go-xmlsig/crypto"
)

// TSData carries the TS-profile artifacts SignTS embeds. asic never
// performs TSA/OCSP I/O; the caller supplies finished artifacts (a TSA
// client response, a basic OCSP response, and the certificates to embed
// in xades:CertificateValues).
type TSData struct {
	// TimeStamp produces an RFC 3161 TST over the given data. SignTS
	// calls it exactly once, with the C14N 1.1 canonical bytes of the
	// document's ds:SignatureValue element — the exact bytes
	// the collector's timestamp check digests when verifying the token.
	TimeStamp func(data []byte) ([]byte, error)

	// OCSPResponse is the DER basic OCSP response for the signer
	// certificate. The collector checks it offline against the OCSP
	// responder certificates in the trust YAML (ocsp responders), and
	// requires
	// producedAt within 1 minute of the declared SigningTime.
	OCSPResponse []byte

	// Certificates are embedded in xades:CertificateValues in order:
	// the OCSP responder certificate first (Id S{k}-RESPONDER_CERT),
	// then the CA-chain certificate (Id S{k}-CA-CERT). Exactly two:
	// the single-ID scheme of xades.Ids.
	Certificates []*x509.Certificate
}

// SignTS renders and cryptographically signs the TS-profile XAdES
// signature document for docs in the given order, signed with key whose
// certificate is cert. All time values come from signingTime (no wall
// clock) — the single-time-T pattern (ADR 0001 §6): SigningTime, the
// OCSP producedAt, and the TST genTime must all be one time so that
// the collector's TS windows (OCSP maxAge 1 min, TSP maxAge 1 min,
// TSDelayTime) are satisfied.
//
// The flow (PLAN.md Task 7): build and sign the S{k} document (BES form:
// SignedInfo and the signature value are independent of UnsignedProperties
// — USP is outside SignedInfo), canonicalize the in-tree ds:SignatureValue
// element, request the TST over those exact bytes via TSData.TimeStamp,
// build the xades:UnsignedProperties element, and add it to the in-tree
// xades:QualifyingProperties (after SignedProperties), then serialize the
// same tree. The SignedInfo and SignatureValue bytes are invariant by
// construction (same tree, deterministic marshal), so the signature and
// the TST imprint both remain valid.
//
// k, sm, dm, and docs carry the same contract as SignBES.
func SignTS(k int, sm xcrypto.XMLSignatureSignerModule, dm xcrypto.XMLDigestModule, cert *x509.Certificate, docs []Doc, signingTime time.Time, ts TSData) ([]byte, error) {
	if ts.TimeStamp == nil {
		return nil, errors.New("asic: TSData.TimeStamp is nil")
	}
	if len(ts.OCSPResponse) == 0 {
		return nil, errors.New("asic: TSData.OCSPResponse is empty")
	}
	if len(ts.Certificates) != 2 {
		return nil, fmt.Errorf("asic: TSData.Certificates must be exactly two (OCSP responder, CA certificate), got %d", len(ts.Certificates))
	}
	for i, c := range ts.Certificates {
		if c == nil {
			return nil, fmt.Errorf("asic: TSData.Certificates[%d] is nil", i)
		}
	}

	files, err := prepareDocs(k, docs)
	if err != nil {
		return nil, err
	}
	sp, err := xades.SignedProperties(k, dm, cert, signingTime.UTC(), files)
	if err != nil {
		return nil, fmt.Errorf("asic: signed properties: %w", err)
	}
	doc, root := sigDocScaffold()
	b := newSigBuilder(k, dm, cert, docs, root, sp)
	sigEl, err := b.BuildSignature(sm)
	if err != nil {
		return nil, fmt.Errorf("asic: build signature: %w", err)
	}
	if err := setSignatureValueId(sigEl, k); err != nil {
		return nil, err
	}

	// Canonicalize the in-tree ds:SignatureValue — the exact bytes
	// the collector's timestamp check digests (inclusive C14N 1.1 in
	// the document
	// namespace context — the same bytes canonicalizeElement produces;
	// ADR 0001 §2).
	sv := sigEl.FindElement("ds:SignatureValue")
	svCanon, err := b.CanonicalizeElement(sv)
	if err != nil {
		return nil, err
	}

	tst, err := ts.TimeStamp(svCanon)
	if err != nil {
		return nil, fmt.Errorf("asic: time-stamp: %w", err)
	}

	usp, err := xades.UnsignedProperties(k, tst, []xades.Certificate{
		{ID: xades.ResponderCertificateID(k), DER: ts.Certificates[0].Raw},
		{ID: xades.CACertificateID(k), DER: ts.Certificates[1].Raw},
	}, ts.OCSPResponse)
	if err != nil {
		return nil, fmt.Errorf("asic: unsigned properties: %w", err)
	}
	qp := sigEl.FindElement("ds:Object/xades:QualifyingProperties")
	if qp == nil {
		return nil, fmt.Errorf("asic: xades:QualifyingProperties missing from built signature")
	}
	qp.AddChild(usp)
	return serializeDoc(doc)
}
