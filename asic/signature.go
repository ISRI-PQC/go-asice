// Signature XML for ASiC-E containers: the minimal BES shape the
// Estonian e-voting collector's schema-driven parser accepts (PLAN.md
// §1.2). The document is built with
// the xmlsig high-level builder — WithRoot for wrapper-root placement,
// WithExternalRef for the data files, WithEmbeddedElement + RefTargetId
// for the XAdES QP→SP pattern — on top of an etree document tree. The
// builder canonicalizes with inclusive C14N 1.1 and computes every digest
// over its element at the final in-document position; the xades property
// builders remain local (shape-compared against the fixtures in
// xades/*_test.go).
//
// The layout is not part of the interop contract: the digests are
// self-referential (we sign the canonical form of the final rendering,
// the collector re-canonicalizes the parsed document), so the hard
// constraints are the TST-flow self-consistency and the collector's
// structural parser (element
// shape/order/Id/Type). The byte-parity quality bar (C14N goldens,
// asic/canon_golden_test.go and asic/sp_digest_golden_test.go) is
// unchanged.
package asic

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/isri-pqc/asice/xades"
	"github.com/isri-pqc/go-xmlsig"
	"github.com/isri-pqc/go-xmlsig/canonicalizers"
	xcrypto "github.com/isri-pqc/go-xmlsig/crypto"
	"github.com/isri-pqc/go-xmlsig/etreeutils"
	"github.com/isri-pqc/go-xmlsig/spec"
)

// Algorithm URIs used by SignedInfo itself (the Estonian e-voting
// collector's accepted set; ADR 0001 section 5). XAdES-side URIs and
// namespaces live in the xades package.
const (
	algC14N11      = "http://www.w3.org/2006/12/xml-c14n11"
	algRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
)

// xmlDeclInst is the content of the XML declaration proc-inst.
const xmlDeclInst = `version="1.0" encoding="UTF-8" standalone="no"`

// SignBES renders and cryptographically signs the minimal BES XAdES
// signature document for docs in the given order, signed with key whose
// certificate is cert. All time values come from signingTime (no wall
// clock). The returned bytes are deterministic for the same inputs
// except the signature itself (ECDSA is randomized).
//
// k is the signature index: the document is meant to be stored as
// META-INF/signatures{k}.xml and every identifier inside it (ds:Signature
// Id, reference Ids, SignatureValue Id, SignedProperties Id, the
// QualifyingProperties Target) derives from it (S{k} scheme, xades.Ids).
// Repeated calls with k = 0, 1, 2, ... yield independent, consistently
// identified signature documents; the collector requires each signature
// document
// to reference ALL data files plus its own SignedProperties (ADR 0002,
// section 1).
func SignBES(k int, sm xcrypto.XMLSignatureSignerModule, dm xcrypto.XMLDigestModule, cert *x509.Certificate, docs []Doc, signingTime time.Time) ([]byte, error) {
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
	return serializeDoc(doc)
}

// prepareDocs validates the signing inputs and builds the
// SignedProperties file descriptions. The data file digests are computed
// by the xmlsig builder from the ExternalRef payloads (ADR 0004).
func prepareDocs(k int, docs []Doc) (files []xades.File, err error) {
	if k < 0 {
		return nil, fmt.Errorf("asic: signature index %d must be >= 0", k)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("asic: no data files to sign")
	}
	files = make([]xades.File, len(docs))
	for i, d := range docs {
		files[i] = xades.File{Name: d.Name, MediaType: d.MediaType}
	}
	return files, nil
}

// sigDocScaffold builds the document scaffold of a signature document:
// XML declaration proc-inst plus the asic:XAdESSignatures root with the
// three namespace bindings (asic, ds, xades). The xmlsig builder appends
// the ds:Signature under the root (WithRoot).
func sigDocScaffold() (*etree.Document, *etree.Element) {
	doc := etree.NewDocument()
	doc.AddChild(etree.NewProcInst("xml", xmlDeclInst))
	root := doc.CreateElement("asic:XAdESSignatures")
	root.CreateAttr("xmlns:asic", xades.NSASIC)
	root.CreateAttr("xmlns:ds", xades.NSDSIG)
	root.CreateAttr("xmlns:xades", xades.NSXAdES)
	return doc, root
}

// newSigBuilder configures the xmlsig builder for the S{k} signature in
// the BDOC 2.1.2 BES shape (the xades.SignedProperties element sp is
// already built):
//
//   - inclusive C14N 1.1 and SHA-256 digests — the builder's defaults,
//     pinned explicitly,
//   - ds:Signature Id S{k} (WithSignatureId),
//   - one raw external reference per data file (WithExternalRef, Raw —
//     data files digest as raw octets and are never canonicalized),
//   - ds:KeyInfo/ds:X509Data/ds:X509Certificate with the single-line
//     base64 of cert.Raw (go-asice's own element via WithKeyInfo),
//   - the xades:QualifyingProperties element embedded in the bare
//     ds:Object (WithEmbeddedElement, InObject), bound by a
//     no-Transforms reference carrying the SignedProperties Type and
//     targeting the nested xades:SignedProperties by its Id
//     (RefTargetId — the XAdES QP→SP pattern; the QP itself carries no
//     Id).
//
// The builder computes every reference digest itself (from the ExternalRef
// data and the embedded element at its final in-document position),
// replacing the hand-rolled reference and SP-digest machinery.
func newSigBuilder(k int, dm xcrypto.XMLDigestModule, cert *x509.Certificate, docs []Doc, root, sp *etree.Element) *xmlsig.XMLSignatureBuilder {
	b := xmlsig.NewXMLSignatureBuilder(dm).
		WithCanonicalizer(canonicalizers.MakeC14N11Canonicalizer()).
		WithDigestMethod(spec.SHA256DigestAlgorithmId).
		WithSignatureId(xades.SignatureID(k)).
		WithRoot(root)
	for i, d := range docs {
		b.WithExternalRef(xmlsig.ExternalRef{
			URI:  d.Name,
			Data: d.Data,
			Id:   xades.ReferenceID(k, i),
			Raw:  true,
		})
	}
	ki := etree.NewElement("ds:KeyInfo")
	ki.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	b.WithKeyInfo(ki)
	b.WithEmbeddedElement(xmlsig.EmbeddedElement{
		Element:     xades.QualifyingProperties(k, sp, nil),
		Type:        xades.SignedPropertiesRefType,
		RefId:       xades.ReferenceID(k, len(docs)),
		InObject:    true,
		RefTargetId: xades.SignedPropertiesID(k),
	})
	return b
}

// setSignatureValueId stamps the S{k}-SIG Id onto the ds:SignatureValue
// the builder emits without an Id. The attribute is outside every
// SignedInfo/SP digest, so setting it after BuildSignature is
// cryptographically inert — but it must be set before any TST-imprint
// canonicalization (SignTS), which must see the final attribute set.
func setSignatureValueId(sigEl *etree.Element, k int) error {
	sv := sigEl.FindElement("ds:SignatureValue")
	if sv == nil {
		return fmt.Errorf("asic: ds:SignatureValue missing from built signature")
	}
	sv.CreateAttr("Id", xades.SignatureValueID(k))
	return nil
}

// serializeDoc renders the final document bytes: WriteToString of the
// tree exactly as the builder left it. The builder computes every digest
// over the live (compact) tree and deliberately bakes no layout into it;
// C14N preserves whitespace-only text, so indenting AFTER signing would
// change the canonical bytes the verifier re-derives from the file (the
// old renderer indented BEFORE signing to keep the two in sync). The
// compact layout is not part of the interop contract (ADR 0001 §3);
// base64 stays single-line (etree writes the text as set).
func serializeDoc(doc *etree.Document) ([]byte, error) {
	s, err := doc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("asic: serialize signature: %w", err)
	}
	return []byte(s), nil
}

// canonicalizeElement canonicalizes el with inclusive C14N 1.1 in its
// in-document namespace context (detached root re-declares the in-scope
// namespaces, mirroring the collector's C14N writer).
func canonicalizeElement(el *etree.Element) ([]byte, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, fmt.Errorf("asic: build namespace context: %w", err)
	}
	canon, err := canonicalizers.CanonicalizeSignedInfo(el, spec.CanonicalXML11AlgorithmId, ctx)
	if err != nil {
		return nil, fmt.Errorf("asic: canonicalize: %w", err)
	}
	return canon, nil
}
