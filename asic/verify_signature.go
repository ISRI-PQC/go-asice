// Per-signature checks of asic.Verify (T8a BES core + T8b TS profile):
// the XML-DSig/XAdES document shape, the signature value (C14N 1.1 of
// SignedInfo verified against the signer certificate), the references
// (data file digests and the SignedProperties digest), the signed
// properties consistency, and — for the TS profile — the
// xades:UnsignedProperties checks (checkTimestamp, checkOCSP,
// TSDelayTime; ADR 0003). The check order mirrors the per-signature
// sequence the Estonian e-voting collector's container verification
// applies.

package asic

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/beevik/etree"
	asiccrypto "github.com/isri-pqc/asice/asic/crypto"
	"github.com/isri-pqc/asice/xades"
	"github.com/isri-pqc/xmlsig/canonicalizers"
	"github.com/isri-pqc/xmlsig/etreeutils"
	"github.com/isri-pqc/xmlsig/spec"
)

// verifySignature runs the full check sequence over one signature
// document (the bytes of META-INF/signaturesN.xml) and returns its
// verdict: the BES core, plus the TS profile checks (checkTimestamp,
// checkOCSP, TSDelayTime) when ts is non-nil. Actionable failures are
// collected in the report; a failed check only prevents checks that
// depend on it.
func verifySignature(ctr *container, name string, doc []byte, m *verifyModules, ts *tsContext) *SignatureReport {
	report := &SignatureReport{}
	fail := func(format string, args ...any) {
		report.Errors = append(report.Errors, fmt.Sprintf(format, args...))
	}

	xd := etree.NewDocument()
	if err := xd.ReadFromBytes(doc); err != nil {
		fail("%s: signature XML parse failed: %v", name, err)
		return finish(report)
	}
	root := xd.Root()
	if namespaceOf(root) != xades.NSASIC || root.Tag != "XAdESSignatures" {
		fail("%s: document root is not asic:XAdESSignatures", name)
		return finish(report)
	}
	if n := len(root.ChildElements()); n != 1 {
		fail("%s: the document root must contain exactly one element, got %d", name, n)
		return finish(report)
	}
	sigs := directElements(root, xades.NSDSIG, "Signature")
	if len(sigs) != 1 {
		fail("%s: the document must contain exactly one ds:Signature, got %d", name, len(sigs))
		return finish(report)
	}
	sig := sigs[0]
	for _, ch := range sig.ChildElements() {
		if namespaceOf(ch) != xades.NSDSIG || !isDSigChild(ch.Tag) {
			fail("%s: unexpected element %s in ds:Signature", name, ch.Tag)
		}
	}
	id := sig.SelectAttrValue("Id", "")
	if id == "" {
		fail("%s: ds:Signature has no Id attribute", name)
		return finish(report)
	}
	report.ID = id
	si := oneDirect(sig, xades.NSDSIG, "SignedInfo", name, fail)
	sv := oneDirect(sig, xades.NSDSIG, "SignatureValue", name, fail)
	ki := oneDirect(sig, xades.NSDSIG, "KeyInfo", name, fail)
	obj := oneDirect(sig, xades.NSDSIG, "Object", name, fail)
	if si == nil || sv == nil || ki == nil || obj == nil {
		return finish(report)
	}
	for _, ch := range si.ChildElements() {
		if namespaceOf(ch) != xades.NSDSIG || !isDSigSignedInfoChild(ch.Tag) {
			fail("%s: unexpected element %s in ds:SignedInfo", name, ch.Tag)
		}
	}

	cert, certOK := checkKeyInfoCert(ki, name, fail)
	if !certOK {
		return finish(report)
	}
	report.Signer = signerName(cert)

	spEl, spOK := checkObject(obj, "#"+id, name, fail)
	if !spOK {
		return finish(report)
	}

	st, stOK := checkSigningTime(spEl, name, fail)
	if !stOK {
		return finish(report)
	}
	report.SigningTime = st

	if err := m.chain.VerifyChain(cert, m.roots, m.intermediates, st); err != nil {
		fail("%s: %v", name, err)
	}
	checkSignatureValue(m, sv, si, cert, name, fail)
	refIDs, refsOK := checkReferences(ctr, m, si, spEl, name, fail)
	if !refsOK {
		return finish(report)
	}
	checkSignedProperties(m, spEl, cert, refIDs, ctr, name, fail)
	if ts != nil {
		checkTSProperties(obj, sv, cert, st, ts, name, report, fail)
	}
	return finish(report)
}

// finish sets the per-signature verdict.
func finish(r *SignatureReport) *SignatureReport {
	r.OK = len(r.Errors) == 0
	return r
}

// signerName renders the signer subject for the report.
func signerName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

// oneDirect returns the unique direct child of el in ns with tag,
// recording an actionable error when the count is not exactly one.
func oneDirect(el *etree.Element, ns, tag, name string, fail func(string, ...any)) *etree.Element {
	ch := directElements(el, ns, tag)
	if len(ch) != 1 {
		fail("%s: exactly one %s element is required, got %d", name, tag, len(ch))
		return nil
	}
	return ch[0]
}

// checkKeyInfoCert extracts the unique ds:X509Certificate of KeyInfo,
// decodes it, and parses it.
func checkKeyInfoCert(ki *etree.Element, name string, fail func(string, ...any)) (*x509.Certificate, bool) {
	certs := descendants(ki, xades.NSDSIG, "X509Certificate")
	if len(certs) != 1 {
		fail("%s: KeyInfo must contain exactly one ds:X509Certificate, got %d", name, len(certs))
		return nil, false
	}
	der, err := decodeBase64(certs[0].Text())
	if err != nil {
		fail("%s: decode X509Certificate base64: %v", name, err)
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fail("%s: parse X509Certificate: %v", name, err)
		return nil, false
	}
	return cert, true
}

// checkObject walks ds:Object → xades:QualifyingProperties →
// xades:SignedProperties, enforcing the QualifyingProperties target
// (the collector's target check) and returning the SP element.
func checkObject(obj *etree.Element, target string, name string, fail func(string, ...any)) (*etree.Element, bool) {
	qp := directElements(obj, xades.NSXAdES, "QualifyingProperties")
	if len(qp) != 1 {
		fail("%s: exactly one QualifyingProperties element is required in ds:Object, got %d", name, len(qp))
		return nil, false
	}
	if t := qp[0].SelectAttrValue("Target", ""); t != target {
		fail("%s: QualifyingProperties Target is %q, want %q", name, t, target)
		return nil, false
	}
	sp := directElements(qp[0], xades.NSXAdES, "SignedProperties")
	if len(sp) != 1 {
		fail("%s: exactly one xades:SignedProperties is required, got %d", name, len(sp))
		return nil, false
	}
	if sp[0].SelectAttrValue("Id", "") == "" {
		fail("%s: xades:SignedProperties has no Id attribute", name)
		return nil, false
	}
	return sp[0], true
}

// checkSigningTime parses xades:SigningTime (RFC 3339) from the SP's
// SignedSignatureProperties.
func checkSigningTime(sp *etree.Element, name string, fail func(string, ...any)) (time.Time, bool) {
	ssp := directElements(sp, xades.NSXAdES, "SignedSignatureProperties")
	if len(ssp) != 1 {
		fail("%s: exactly one xades:SignedSignatureProperties is required, got %d", name, len(ssp))
		return time.Time{}, false
	}
	sts := directElements(ssp[0], xades.NSXAdES, "SigningTime")
	if len(sts) != 1 {
		fail("%s: exactly one xades:SigningTime is required, got %d", name, len(sts))
		return time.Time{}, false
	}
	st, err := time.Parse(time.RFC3339, strings.TrimSpace(sts[0].Text()))
	if err != nil {
		fail("%s: SigningTime %q is not RFC 3339", name, strings.TrimSpace(sts[0].Text()))
		return time.Time{}, false
	}
	return st, true
}

// checkSignatureValue canonicalizes SignedInfo (inclusive C14N 1.1 in
// its document namespace context — byte-identical to the signing path,
// asic/canon_golden_test.go) and verifies the base64 SignatureValue
// against the signer certificate through the verifier module (ADR
// 0004; the standard module verifies RSA-PKCS#1 v1.5, or ECDSA with
// the r||s value re-encoded to ASN.1 — the inverse of the
// ecdsa.SignASN1-derived encoding the signer path emits).
func checkSignatureValue(m *verifyModules, sv, si *etree.Element, cert *x509.Certificate, name string, fail func(string, ...any)) {
	cm := directElements(si, xades.NSDSIG, "CanonicalizationMethod")
	if len(cm) != 1 {
		fail("%s: exactly one ds:CanonicalizationMethod is required, got %d", name, len(cm))
		return
	}
	if alg := cm[0].SelectAttrValue("Algorithm", ""); alg != algC14N11 {
		fail("%s: unsupported canonicalization method %q", name, alg)
		return
	}
	sm := directElements(si, xades.NSDSIG, "SignatureMethod")
	if len(sm) != 1 {
		fail("%s: exactly one ds:SignatureMethod is required, got %d", name, len(sm))
		return
	}
	sigAlg := sm[0].SelectAttrValue("Algorithm", "")
	if _, ok := signatureMethods[spec.XMLSignatureAlgorithmID(sigAlg)]; !ok {
		fail("%s: unsupported signature method %q", name, sigAlg)
		return
	}
	canon, err := canonicalizeSignedInfoBytes(si)
	if err != nil {
		fail("%s: canonicalize SignedInfo: %v", name, err)
		return
	}
	sigVal, err := decodeBase64(sv.Text())
	if err != nil {
		fail("%s: decode SignatureValue base64: %v", name, err)
	}
	if err := m.verifier.VerifySignedInfo(canon, cert.Raw, sigVal, spec.XMLSignatureAlgorithmID(sigAlg)); err != nil {
		fail("%s: signature verification failed: %v", name, err)
	}
}

// signatureMethods is the allowlist of ds:SignatureMethod algorithms
// (the collector's accepted set: RSA and ECDSA with
// SHA-256/384/512) — the interop contract, checked here; the
// verification itself is the
// verifier module's job (ADR 0004).
var signatureMethods = map[spec.XMLSignatureAlgorithmID]struct{}{
	spec.RSASHA256SignatureMethod:   {},
	spec.RSASHA384SignatureMethod:   {},
	spec.RSASHA512SignatureMethod:   {},
	spec.ECDSASHA256SignatureMethod: {},
	spec.ECDSASHA384SignatureMethod: {},
	spec.ECDSASHA512SignatureMethod: {},
}

// checkReferences verifies every ds:Reference of the signature (the
// collector's reference check): exactly one SignedProperties reference
// plus exactly
// one file reference per container data file, unique Ids and URIs, and
// matching SHA-256 digests — the file digests over the raw entry bytes,
// the SignedProperties digest over the canonicalized SP element.
func checkReferences(ctr *container, m *verifyModules, si, spEl *etree.Element, name string, fail func(string, ...any)) (map[string]string, bool) {
	refIDs := make(map[string]string)
	refs := directElements(si, xades.NSDSIG, "Reference")
	var spRef *etree.Element
	var fileRefs []*etree.Element
	for _, ref := range refs {
		t := ref.SelectAttrValue("Type", "")
		if t != "" && t != xades.SignedPropertiesRefType {
			fail("%s: unsupported reference Type %q", name, t)
			continue
		}
		if t == xades.SignedPropertiesRefType {
			if spRef != nil {
				fail("%s: more than one SignedProperties reference", name)
				spRef = nil
			} else {
				spRef = ref
			}
			continue
		}
		fileRefs = append(fileRefs, ref)
		id := ref.SelectAttrValue("Id", "")
		if id == "" {
			fail("%s: a file reference has no Id attribute", name)
			continue
		}
		if _, dup := refIDs[id]; dup {
			fail("%s: duplicate reference Id %q", name, id)
			continue
		}
		refIDs[id] = ref.SelectAttrValue("URI", "")
	}
	if spRef == nil {
		fail("%s: no SignedProperties reference (Type %s)", name, xades.SignedPropertiesRefType)
	}
	if len(fileRefs) != len(ctr.files) {
		fail("%s: the signature references %d data files, the container has %d", name, len(fileRefs), len(ctr.files))
	}
	seenURI := make(map[string]struct{}, len(fileRefs))
	for _, ref := range fileRefs {
		uri := ref.SelectAttrValue("URI", "")
		if strings.HasPrefix(uri, "#") || uri == "" {
			fail("%s: file reference URI %q must be a bare data file name", name, uri)
			continue
		}
		if _, dup := seenURI[uri]; dup {
			fail("%s: duplicate file reference URI %q", name, uri)
			continue
		}
		seenURI[uri] = struct{}{}
		data, ok := ctr.files[uri]
		if !ok {
			fail("%s: reference URI %q does not match a data file in the container", name, uri)
			continue
		}
		if err := checkRefDigest(m, ref, data, uri); err != nil {
			fail("%s: %v", name, err)
		}
	}
	if spRef != nil {
		if uri := spRef.SelectAttrValue("URI", ""); uri != "#"+spEl.SelectAttrValue("Id", "") {
			fail("%s: SignedProperties reference URI %q, want %q", name, uri, "#"+spEl.SelectAttrValue("Id", ""))
		} else {
			canon, err := canonicalizeSignedInfoBytes(spEl)
			if err != nil {
				fail("%s: canonicalize SignedProperties: %v", name, err)
			} else {
				digest, err := m.digest.GetDigestFunc(spec.XMLDigestAlgorithmID(xades.DigestMethodSHA256))(canon)
				if err != nil {
					fail("%s: SignedProperties digest: %v", name, err)
				} else if err := digestMatches(spRef, digest); err != nil {
					fail("%s: SignedProperties digest mismatch: %v", name, err)
				}
			}
		}
	}
	return refIDs, spRef != nil && len(fileRefs) == len(ctr.files)
}

// refDigests is the (method, value) pair of a ds:Reference.
type refDigest struct {
	method string
	value  string
}

// refDigestOf extracts the DigestMethod/DigestValue of a reference.
func refDigestOf(ref *etree.Element) refDigest {
	dm := directElements(ref, xades.NSDSIG, "DigestMethod")
	dv := directElements(ref, xades.NSDSIG, "DigestValue")
	if len(dm) != 1 || len(dv) != 1 {
		return refDigest{}
	}
	return refDigest{method: dm[0].SelectAttrValue("Algorithm", ""), value: dv[0].Text()}
}

// checkRefDigest verifies one file reference's digest (through the
// digest module — ADR 0004).
func checkRefDigest(m *verifyModules, ref *etree.Element, data []byte, uri string) error {
	d := refDigestOf(ref)
	if d.method != xades.DigestMethodSHA256 {
		return fmt.Errorf("reference %q: unsupported digest method %q", uri, d.method)
	}
	digest, err := m.digest.GetDigestFunc(spec.XMLDigestAlgorithmID(d.method))(data)
	if err != nil {
		return fmt.Errorf("reference %q: digest: %w", uri, err)
	}
	if err := digestMatchesValue(d.value, digest); err != nil {
		return fmt.Errorf("digest mismatch for file %q: %v", uri, err)
	}
	return nil
}

// digestMatches verifies the reference's DigestValue against digest.
func digestMatches(ref *etree.Element, digest []byte) error {
	return digestMatchesValue(refDigestOf(ref).value, digest)
}

// digestMatchesValue compares a (whitespace-wrapped) base64 digest
// value against the raw digest bytes.
func digestMatchesValue(value string, digest []byte) error {
	got, err := decodeBase64(value)
	if err != nil {
		return fmt.Errorf("decode stored digest: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(digest)
	gotStr := base64.StdEncoding.EncodeToString(got)
	if gotStr != want {
		return fmt.Errorf("stored digest %s, want %s", gotStr, want)
	}
	return nil
}

// checkSignedProperties verifies the signed properties consistency
// (the collector's SignedProperties check + the DataObjectFormat
// cross-checks of checkReferences): the SigningCertificate must
// describe the signer
// certificate (CertDigest over the KeyInfo certificate DER, matching
// issuer name and serial), SignaturePolicyIdentifier must be absent
// (TM-profile signatures are rejected in the BES and TS profiles), and
// every DataObjectFormat must resolve to a distinct container data
// file whose ODF media type matches.
func checkSignedProperties(m *verifyModules, sp *etree.Element, cert *x509.Certificate, refIDs map[string]string, ctr *container, name string, fail func(string, ...any)) {
	ssp := directElements(sp, xades.NSXAdES, "SignedSignatureProperties")
	if len(ssp) != 1 {
		fail("%s: exactly one xades:SignedSignatureProperties is required, got %d", name, len(ssp))
		return
	}
	if spi := descendants(ssp[0], xades.NSXAdES, "SignaturePolicyIdentifier"); len(spi) > 0 {
		fail("%s: SignaturePolicyIdentifier present: TM-profile signatures are rejected in the BES and TS profiles", name)
	}
	scs := directElements(ssp[0], xades.NSXAdES, "SigningCertificate")
	if len(scs) != 1 {
		fail("%s: exactly one xades:SigningCertificate is required, got %d", name, len(scs))
		return
	}
	certs := directElements(scs[0], xades.NSXAdES, "Cert")
	if len(certs) != 1 {
		fail("%s: exactly one xades:Cert is required, got %d", name, len(certs))
		return
	}
	certEl := certs[0]
	cds := directElements(certEl, xades.NSXAdES, "CertDigest")
	if len(cds) != 1 {
		fail("%s: exactly one xades:CertDigest is required, got %d", name, len(cds))
		return
	}
	certDigest, err := m.digest.GetDigestFunc(spec.XMLDigestAlgorithmID(xades.DigestMethodSHA256))(cert.Raw)
	if err != nil {
		fail("%s: SigningCertificate CertDigest: %v", name, err)
	} else if err := digestMatches(cds[0], certDigest); err != nil {
		fail("%s: SigningCertificate CertDigest does not match the KeyInfo certificate: %v", name, err)
	}
	iss := directElements(certEl, xades.NSXAdES, "IssuerSerial")
	if len(iss) != 1 {
		fail("%s: exactly one xades:IssuerSerial is required, got %d", name, len(iss))
		return
	}
	isEl := iss[0]
	serials := directElements(isEl, xades.NSDSIG, "X509SerialNumber")
	if len(serials) != 1 || strings.TrimSpace(serials[0].Text()) != cert.SerialNumber.String() {
		fail("%s: SigningCertificate serial does not match the KeyInfo certificate serial", name)
	}
	issuers := directElements(isEl, xades.NSDSIG, "X509IssuerName")
	if len(issuers) != 1 || strings.TrimSpace(issuers[0].Text()) != xades.IssuerName(cert) {
		fail("%s: SigningCertificate issuer does not match the KeyInfo certificate issuer", name)
	}

	dofs := directDataObjectFormats(sp)
	if len(dofs) != len(ctr.files) {
		fail("%s: the signed properties describe %d data files, the container has %d", name, len(dofs), len(ctr.files))
		return
	}
	covered := make(map[string]struct{}, len(dofs))
	for _, dof := range dofs {
		objRef := dof.SelectAttrValue("ObjectReference", "")
		if !strings.HasPrefix(objRef, "#") {
			fail("%s: DataObjectFormat ObjectReference %q must be a fragment reference", name, objRef)
			continue
		}
		fileURI, ok := refIDs[objRef[1:]]
		if !ok {
			fail("%s: DataObjectFormat ObjectReference %q does not match a reference Id", name, objRef)
			continue
		}
		mts := directElements(dof, xades.NSXAdES, "MimeType")
		if len(mts) != 1 {
			fail("%s: exactly one xades:MimeType is required per DataObjectFormat, got %d", name, len(mts))
			continue
		}
		mediaType, ok := ctr.manifest[fileURI]
		if !ok {
			fail("%s: DataObjectFormat resolves to %q, which is not a container data file", name, fileURI)
			continue
		}
		if mt := strings.TrimSpace(mts[0].Text()); mt != mediaType {
			fail("%s: DataObjectFormat media type %q for %q, manifest says %q", name, mt, fileURI, mediaType)
			continue
		}
		covered[fileURI] = struct{}{}
	}
	if len(covered) != len(ctr.files) {
		fail("%s: the signed properties do not cover every container data file exactly once", name)
	}
}

// directDataObjectFormats returns the xades:DataObjectFormat elements
// under the SP's SignedDataObjectProperties (none when absent).
func directDataObjectFormats(sp *etree.Element) []*etree.Element {
	sdos := directElements(sp, xades.NSXAdES, "SignedDataObjectProperties")
	if len(sdos) != 1 {
		return nil
	}
	return directElements(sdos[0], xades.NSXAdES, "DataObjectFormat")
}

// --- XML helpers (prefix-agnostic element search over etree) ---

// isDSigChild reports whether tag is one of the four ds:Signature
// children the BES shape allows.
func isDSigChild(tag string) bool {
	switch tag {
	case "SignedInfo", "SignatureValue", "KeyInfo", "Object":
		return true
	}
	return false
}

// isDSigSignedInfoChild reports whether tag is one of the ds:SignedInfo
// children the BES shape allows.
func isDSigSignedInfoChild(tag string) bool {
	switch tag {
	case "CanonicalizationMethod", "SignatureMethod", "Reference":
		return true
	}
	return false
}

// namespaceOf resolves the namespace of el (its own prefix bound in the
// document).
func namespaceOf(el *etree.Element) string {
	surrounding, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return ""
	}
	sub, err := surrounding.SubContext(el)
	if err != nil {
		return ""
	}
	ns, err := sub.LookupPrefix(el.Space)
	if err != nil {
		return ""
	}
	return ns
}

// directElements returns the direct child elements of el in the given
// namespace and tag, in document order.
func directElements(el *etree.Element, ns, tag string) []*etree.Element {
	surrounding, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil
	}
	sub, err := surrounding.SubContext(el)
	if err != nil {
		return nil
	}
	var out []*etree.Element
	for _, ch := range el.ChildElements() {
		cctx, err := sub.SubContext(ch)
		if err != nil {
			continue
		}
		cur, err := cctx.LookupPrefix(ch.Space)
		if err != nil {
			continue
		}
		if cur == ns && ch.Tag == tag {
			out = append(out, ch)
		}
	}
	return out
}

// descendants counts-and-collects every element (any depth, including
// el itself) in the given namespace and tag under el.
func descendants(el *etree.Element, ns, tag string) []*etree.Element {
	surrounding, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil
	}
	var out []*etree.Element
	err = etreeutils.NSFindIterateCtx(surrounding, el, ns, tag, func(_ etreeutils.NSContext, e *etree.Element) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil
	}
	return out
}

// canonicalizeSignedInfoBytes canonicalizes el with inclusive C14N 1.1
// in its in-document namespace context — the same call the signing
// path uses (asic.SignBES → canonicalizeElement), so verify re-hashes
// the identical bytes.
func canonicalizeSignedInfoBytes(el *etree.Element) ([]byte, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, fmt.Errorf("build namespace context: %w", err)
	}
	canon, err := canonicalizers.CanonicalizeSignedInfo(el, spec.CanonicalXML11AlgorithmId, ctx)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return canon, nil
}

// decodeBase64 decodes a base64 value that may carry whitespace
// (our renderer emits single-line base64; the collector strips
// whitespace before decoding, so both layouts verify).
func decodeBase64(s string) ([]byte, error) {
	clean := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(s)
	b, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// --- TS profile checks (T8b, ADR 0003) ---

// tsDelayTime is the collector's TSDelayTime (the trust YAML
// "tsdelaytime: 60"):
// the bound of the TST genTime and OCSP producedAt difference
// (ADR 0003 section 2): 0 <= producedAt - genTime <= tsDelayTime.
const tsDelayTime = 60 * time.Second

// ocspThisUpdateMaxAge is the collector's OCSP maxAge (maxAge = 1
// minute) for the STORED (offline) response path: the bound of
// producedAt - thisUpdate. The now-based skew/age checks apply to the
// LIVE path only and never run on stored responses.
const ocspThisUpdateMaxAge = 1 * time.Minute

var (
	// oidOCSPBasic is the id-pkix-OCSP BasicOCSPResponse content type
	// (RFC 6960 section 4.2.1).
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	// oidOCSPSHA1 is the SHA-1 digest OID — the CertID issuer name
	// hash algorithm the collector's CertID construction uses.
	oidOCSPSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// ocspSignatureAlgorithms is the allowlist of OCSP response signature
// algorithm OIDs the collector accepts (the RSA SHA-2/3/4 variants
// only) — the interop contract, checked here; the verification itself
// is the OCSP module's job (ADR 0004).
var ocspSignatureAlgorithms = map[string]struct{}{
	"1.2.840.113549.1.1.11": {},
	"1.2.840.113549.1.1.12": {},
	"1.2.840.113549.1.1.13": {},
}

// checkTSProperties runs the TS profile checks of one signature
// (the collector's TS-profile branch): the
// xades:UnsignedProperties strict
// shape, checkTimestamp (TST over the C14N 1.1 ds:SignatureValue
// element), checkOCSP (the embedded OCSP response), and the TSDelayTime
// bound. A failed check stops the checks that depend on it; on success
// the report SigningTime is REPLACED with the TST genTime (the
// collector's timestamp-check behavior).
func checkTSProperties(obj, sv *etree.Element, cert *x509.Certificate, declaredSigningTime time.Time, ts *tsContext, name string, report *SignatureReport, fail func(string, ...any)) {
	tst, ocspDER, ok := checkUSPShape(obj, name, fail)
	if !ok {
		return
	}
	genTime, ok := checkTimestampTS(tst, sv, ts, name, fail)
	if !ok {
		return
	}
	producedAt, ok := checkOCSPResponse(ocspDER, cert, declaredSigningTime, ts, name, fail)
	if !ok {
		return
	}
	// The collector's timestamp/OCSP time-mismatch bound (ADR 0003 section 2).
	if diff := producedAt.Sub(genTime); diff < 0 || diff > tsDelayTime {
		fail("%s: OCSP producedAt %s and TST genTime %s differ by %s, the TSDelayTime bound is %s",
			name, producedAt.UTC().Format(time.RFC3339), genTime.UTC().Format(time.RFC3339), diff, tsDelayTime)
		return
	}
	report.SigningTime = genTime
}

// checkUSPShape enforces the strict xades:UnsignedProperties shape
// (ADR 0003 section 3; the collector's schema-driven parser rejects
// unknown/mis-ordered elements) and returns the embedded TST and OCSP
// response bytes:
//
//	xades:UnsignedSignatureProperties
//	  xades:SignatureTimeStamp          (REQUIRED for the TS profile)
//	    [xades:CanonicalizationMethod]  (optional; C14N 1.1 only)
//	    xades:EncapsulatedTimeStamp     (exactly one; base64 DER TST)
//	  xades:CertificateValues
//	    xades:EncapsulatedX509Certificate (at least one; values not
//	    validated — the collector checks presence only)
//	  xades:RevocationValues
//	    xades:OCSPValues                (exactly one; no CRL values)
//	      xades:EncapsulatedOCSPValue   (exactly one; base64 DER OCSP)
func checkUSPShape(obj *etree.Element, name string, fail func(string, ...any)) ([]byte, []byte, bool) {
	qp := directElements(obj, xades.NSXAdES, "QualifyingProperties")
	if len(qp) != 1 {
		fail("%s: exactly one xades:QualifyingProperties is required in ds:Object, got %d", name, len(qp))
		return nil, nil, false
	}
	usps := directElements(qp[0], xades.NSXAdES, "UnsignedProperties")
	switch len(usps) {
	case 0:
		fail("%s: xades:UnsignedProperties missing: the signature time-stamp is required for the TS profile", name)
		return nil, nil, false
	case 1:
	default:
		fail("%s: exactly one xades:UnsignedProperties is required, got %d", name, len(usps))
		return nil, nil, false
	}
	sps := directElements(usps[0], xades.NSXAdES, "UnsignedSignatureProperties")
	if len(sps) != 1 {
		fail("%s: exactly one xades:UnsignedSignatureProperties is required, got %d", name, len(sps))
		return nil, nil, false
	}

	// The strict child order (ADR 0003 section 3).
	want := []string{"SignatureTimeStamp", "CertificateValues", "RevocationValues"}
	var tsEl, cvEl, rvEl *etree.Element
	slot := 0
	for _, ch := range sps[0].ChildElements() {
		if namespaceOf(ch) != xades.NSXAdES {
			fail("%s: unexpected element %s in xades:UnsignedSignatureProperties", name, ch.Tag)
			continue
		}
		if slot >= len(want) || ch.Tag != want[slot] {
			fail("%s: unexpected element %s in xades:UnsignedSignatureProperties (strict order: %s)", name, ch.Tag, strings.Join(want, ", "))
			continue
		}
		switch ch.Tag {
		case "SignatureTimeStamp":
			tsEl = ch
		case "CertificateValues":
			cvEl = ch
		case "RevocationValues":
			rvEl = ch
		}
		slot++
	}
	if tsEl == nil {
		fail("%s: xades:SignatureTimeStamp missing from xades:UnsignedSignatureProperties (required for the TS profile)", name)
		return nil, nil, false
	}
	if cvEl == nil {
		fail("%s: xades:CertificateValues missing from xades:UnsignedSignatureProperties", name)
		return nil, nil, false
	}
	if rvEl == nil {
		fail("%s: xades:RevocationValues missing from xades:UnsignedSignatureProperties", name)
		return nil, nil, false
	}
	// SignatureTimeStamp: [CanonicalizationMethod?] + exactly one
	// EncapsulatedTimeStamp; nothing else. The CanonicalizationMethod
	// may carry the ds: or xades: prefix (the testMIDTS fixture uses
	// ds:) and must be the C14N 1.1 algorithm when present (the
	// collector's timestamp check).
	var tstB64 string
	for _, ch := range tsEl.ChildElements() {
		ns := namespaceOf(ch)
		switch {
		case ch.Tag == "CanonicalizationMethod" && (ns == xades.NSDSIG || ns == xades.NSXAdES):
			if alg := ch.SelectAttrValue("Algorithm", ""); alg != algC14N11 {
				fail("%s: unsupported timestamp canonicalization algorithm %q", name, alg)
			}
		case ns == xades.NSXAdES && ch.Tag == "EncapsulatedTimeStamp":
			if tstB64 != "" {
				fail("%s: more than one xades:EncapsulatedTimeStamp in xades:SignatureTimeStamp", name)
				tstB64 = ""
			}
			tstB64 = ch.Text()
		default:
			fail("%s: unexpected element %s in xades:SignatureTimeStamp", name, ch.Tag)
		}
	}
	if tstB64 == "" {
		fail("%s: no xades:EncapsulatedTimeStamp in xades:SignatureTimeStamp: the TST is required for the TS profile", name)
		return nil, nil, false
	}
	tst, err := decodeBase64(tstB64)
	if err != nil {
		fail("%s: decode EncapsulatedTimeStamp base64: %v", name, err)
		return nil, nil, false
	}
	// CertificateValues: at least one embedded certificate (presence
	// only — the collector does not validate the certificate values).
	certs := directElements(cvEl, xades.NSXAdES, "EncapsulatedX509Certificate")
	if len(certs) == 0 {
		fail("%s: xades:CertificateValues has no xades:EncapsulatedX509Certificate", name)
		return nil, nil, false
	}
	for _, ch := range cvEl.ChildElements() {
		if namespaceOf(ch) == xades.NSXAdES && ch.Tag != "EncapsulatedX509Certificate" {
			fail("%s: unexpected element %s in xades:CertificateValues", name, ch.Tag)
		}
	}
	// RevocationValues: exactly one OCSPValues (no CRL values),
	// holding exactly one EncapsulatedOCSPValue.
	ocsvs := directElements(rvEl, xades.NSXAdES, "OCSPValues")
	for _, ch := range rvEl.ChildElements() {
		if namespaceOf(ch) == xades.NSXAdES && ch.Tag != "OCSPValues" {
			fail("%s: unexpected element %s in xades:RevocationValues (CRL values are not allowed)", name, ch.Tag)
		}
	}
	if len(ocsvs) != 1 {
		fail("%s: exactly one xades:OCSPValues is required in xades:RevocationValues, got %d", name, len(ocsvs))
		return nil, nil, false
	}
	ocsps := directElements(ocsvs[0], xades.NSXAdES, "EncapsulatedOCSPValue")
	if len(ocsps) != 1 {
		fail("%s: exactly one xades:EncapsulatedOCSPValue is required, got %d", name, len(ocsps))
		return nil, nil, false
	}
	ocspDER, err := decodeBase64(ocsps[0].Text())
	if err != nil {
		fail("%s: decode EncapsulatedOCSPValue base64: %v", name, err)
		return nil, nil, false
	}
	return tst, ocspDER, true
}

// checkTimestampTS mirrors the collector's timestamp check (offline
// path): the embedded TST is verified over the C14N 1.1 canonical
// ds:SignatureValue element — the TST message imprint is the digest of
// exactly those bytes (ADR 0003 section 1). It returns the TST genTime.
// The offline TST verifier does not check genTime against the current
// time (the collector's stored-token path either); staleness is
// defended by the TSDelayTime comparison instead.
//
// The TST verifier carries the TSA-signer pool as its trust boundary
// (ADR 0004): the collector's offline TST check identifies the signer
// from the trust YAML tsp.signers list and never chains it to a PKI
// root (the
// 2023 SK fixtures' TSA CA is not in the trust YAML either), so the
// standard verifier is configured with the pool as its root set — a
// pool entry verifies as its own root, and a TST signed by a
// certificate outside the pool is still rejected.
func checkTimestampTS(tst []byte, sv *etree.Element, ts *tsContext, name string, fail func(string, ...any)) (time.Time, bool) {
	canon, err := canonicalizeSignedInfoBytes(sv)
	if err != nil {
		fail("%s: canonicalize SignatureValue for the TST imprint: %v", name, err)
		return time.Time{}, false
	}
	gen, err := ts.tstVerifier.VerifyTST(tst, canon)
	if err != nil {
		fail("%s: signature time-stamp verification failed: %v", name, err)
		return time.Time{}, false
	}
	return gen, true
}

// checkOCSPResponse mirrors the collector's OCSP check over the STORED
// (offline) response (the full-response check at the signature time):
// the embedded OCSP
// response is unmarshaled, its status must be Good for the signer
// certificate's certID, the response signature must verify with the
// responder (the configured responder, or the signer's issuer
// fallback), and producedAt must lie within [thisUpdate,
// thisUpdate + 1 minute] (the collector's stored-response window). It
// returns the producedAt.
func checkOCSPResponse(ocspDER []byte, cert *x509.Certificate, sigTime time.Time, ts *tsContext, name string, fail func(string, ...any)) (time.Time, bool) {
	var outer ocspOuter
	rest, err := asn1.Unmarshal(ocspDER, &outer)
	if err != nil || len(rest) > 0 {
		fail("%s: decode embedded OCSP response: %v", name, err)
		return time.Time{}, false
	}
	if int(outer.ResponseStatus) != 0 {
		fail("%s: OCSP response status is %d, want successful(0)", name, int(outer.ResponseStatus))
		return time.Time{}, false
	}
	if !outer.ResponseBytes.ResponseType.Equal(oidOCSPBasic) {
		fail("%s: OCSP response type is %s, want id-pkix-OCSP (%s)", name, outer.ResponseBytes.ResponseType, oidOCSPBasic)
		return time.Time{}, false
	}
	var basic ocspBasic
	rest, err = asn1.Unmarshal(outer.ResponseBytes.Response, &basic)
	if err != nil || len(rest) > 0 {
		fail("%s: decode OCSP basic response: %v", name, err)
		return time.Time{}, false
	}
	rd := basic.TBSResponseData
	if n := len(rd.Responses); n != 1 {
		fail("%s: the OCSP response has %d singleResponses, want 1", name, n)
		return time.Time{}, false
	}
	single := rd.Responses[0]
	// CertStatus "good": the empty context [0] form (80 00) of RFC
	// 6960 section 2.3.
	if !bytes.Equal(single.Status.FullBytes, []byte{0x80, 0x00}) {
		fail("%s: OCSP certificate status is not Good (raw % x)", name, single.Status.FullBytes)
		return time.Time{}, false
	}
	// certID match (the collector's CertID: SHA-1 of the issuer name
	// DER, the issuer key from the AuthorityKeyId extension, the
	// serial).
	nameHash := sha1.Sum(cert.RawIssuer)
	cid := single.CertID
	if !cid.HashAlgorithm.Algorithm.Equal(oidOCSPSHA1) {
		fail("%s: the OCSP response certID hash algorithm is %s, want SHA-1 (%s)", name, cid.HashAlgorithm.Algorithm, oidOCSPSHA1)
		return time.Time{}, false
	}
	if !bytes.Equal(cid.IssuerNameHash, nameHash[:]) || !bytes.Equal(cid.IssuerKeyHash, cert.AuthorityKeyId) ||
		cid.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		fail("%s: the OCSP response certID does not match the signer certificate", name)
		return time.Time{}, false
	}
	// The responder and the response signature over the tbsResponseData.
	issuer := issuerCertificate(cert, ts.roots, ts.intermediates)
	responder, err := ocspResponder(ts.ocspModule, rd.ResponderIDByName, basic.Certs, ts.ocspResponders, issuer, sigTime)
	if err != nil {
		fail("%s: OCSP responder: %v", name, err)
		return time.Time{}, false
	}
	if _, ok := ocspSignatureAlgorithms[basic.SignatureAlgorithm.Algorithm.String()]; !ok {
		fail("%s: unsupported OCSP response signature algorithm %s", name, basic.SignatureAlgorithm.Algorithm)
		return time.Time{}, false
	}
	if err := ts.ocspModule.VerifyResponseSignature(responder, rd.Raw, basic.Signature.RightAlign(), basic.SignatureAlgorithm.Algorithm); err != nil {
		fail("%s: %v", name, err)
		return time.Time{}, false
	}
	// The stored-response window (the collector's stored-response check):
	// producedAt >= thisUpdate and producedAt - thisUpdate <= maxAge.
	if rd.ProducedAt.Before(single.ThisUpdate) {
		fail("%s: OCSP producedAt %s is before thisUpdate %s", name,
			rd.ProducedAt.UTC().Format(time.RFC3339), single.ThisUpdate.UTC().Format(time.RFC3339))
		return time.Time{}, false
	}
	if age := rd.ProducedAt.Sub(single.ThisUpdate); age > ocspThisUpdateMaxAge {
		fail("%s: OCSP producedAt %s is %s after thisUpdate (max %s)", name,
			rd.ProducedAt.UTC().Format(time.RFC3339), age, ocspThisUpdateMaxAge)
		return time.Time{}, false
	}
	return rd.ProducedAt, true
}

// ocspResponder finds the certificate that must have signed the
// response (mirroring the collector's responder identification): first
// a configured
// responder whose subject matches the response ResponderID name, then
// the issuer fallback — the first embedded certificate with a matching
// subject that chains to the signer's issuer with the OCSPSigning EKU
// (a name-matching certificate that fails the chain verification is an
// error, per the collector).
func ocspResponder(m asiccrypto.OCSPVerifierModule, name pkix.RDNSequence, embedded []asn1.RawValue, configured []*x509.Certificate, issuer *x509.Certificate, at time.Time) (*x509.Certificate, error) {
	for _, r := range configured {
		r.Subject.ExtraNames = r.Subject.Names
		if rdnSequenceEqual(r.Subject.ToRDNSequence(), name) {
			return r, nil
		}
	}
	if issuer == nil {
		return nil, fmt.Errorf("no issuer certificate available to verify the embedded OCSP responder %s", name)
	}
	for _, der := range embedded {
		cert, err := x509.ParseCertificate(der.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("parse embedded OCSP responder certificate: %w", err)
		}
		cert.Subject.ExtraNames = cert.Subject.Names
		if !rdnSequenceEqual(cert.Subject.ToRDNSequence(), name) {
			continue
		}
		if err := m.VerifyResponderCertificate(cert, issuer, at); err != nil {
			return nil, err
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no OCSP responder certificate matches the response responder name %s", name)
}

// issuerCertificate finds the signer's issuer certificate among the
// supplied trust certificates (the collector's configured issuer
// trust set used for the OCSP check).
func issuerCertificate(cert *x509.Certificate, roots, intermediates []*x509.Certificate) *x509.Certificate {
	pool := make([]*x509.Certificate, 0, len(roots)+len(intermediates))
	pool = append(pool, intermediates...)
	pool = append(pool, roots...)
	for _, c := range pool {
		if bytes.Equal(c.RawSubject, cert.RawIssuer) {
			return c
		}
	}
	return nil
}

// rdnSequenceEqual compares two RDN sequences attribute by attribute
// (same order, type and value) — the responder-name match semantics
// the collector uses.
func rdnSequenceEqual(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			av, bv := a[i][j], b[i][j]
			if !av.Type.Equal(bv.Type) {
				return false
			}
			switch x := av.Value.(type) {
			case string:
				y, ok := bv.Value.(string)
				if !ok || x != y {
					return false
				}
			case []byte:
				y, ok := bv.Value.([]byte)
				if !ok || !bytes.Equal(x, y) {
					return false
				}
			default:
				if fmt.Sprint(av.Value) != fmt.Sprint(bv.Value) {
					return false
				}
			}
		}
	}
	return true
}

// --- embedded OCSP response (RFC 6960) decode types ---
//
// Same field order, tags and optionals as the OCSP response shapes
// the collector unmarshals (and testutil, which builds the generated
// responses).

// ocspOuter is the OCSPResponse wrapper; only the "successful" form
// (responseBytes present) is accepted — the other statuses are
// rejected on the status field.
type ocspOuter struct {
	ResponseStatus asn1.Enumerated
	ResponseBytes  ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// ocspBasic is the BasicOCSPResponse (RFC 6960 section 4.2.1).
type ocspBasic struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	// Certs is the optional [0] field carrying the responder
	// certificate(s).
	Certs []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type ocspResponseData struct {
	// Raw preserves the full tbsResponseData encoding (the bytes the
	// response signature covers).
	Raw               asn1.RawContent
	ResponderIDByName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	ProducedAt        time.Time
	Responses         []ocspSingleResponse
	ResponseExt       []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspSingleResponse struct {
	CertID ocspCertID
	// Status is the CertStatus CHOICE; "good" is the empty [0] form
	// (80 00).
	Status     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time        `asn1:"explicit,tag:0,optional"`
	SingleExt  []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// ocspCertID is the CertID (RFC 6960 section 4.1.1): the issuer name
// hash (SHA-1), the issuer key hash (the AuthorityKeyId extension) and
// the serial number.
type ocspCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}
