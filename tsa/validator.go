package tsa

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	tcrypto "github.com/isri-pqc/go-asice/tsa/crypto"
)

// Default freshness bounds (ADR 0001 section 5; the defaults of the
// Estonian e-voting collector's TSP client): the maximum age of a
// genTime (now - genTime) and the maximum it may be set into the
// future.
const (
	DefaultMaxAge  = 1 * time.Minute
	DefaultMaxSkew = 2 * time.Second
)

// CMS signed-attribute OIDs (RFC 5652 section 11, RFC 5755) in string
// form (the collector's lookups are string-keyed too).
const (
	oidAttrContentType   = "1.2.840.113549.1.9.3"
	oidAttrMessageDigest = "1.2.840.113549.1.9.4"
	oidAttrSigningTime   = "1.2.840.113549.1.9.5"
	oidAttrSigningCert   = "1.2.840.113549.1.9.16.2.12"
	oidAttrSigningCertV2 = "1.2.840.113549.1.9.16.2.47"
	// id-cms-algorithmProtection (RFC 6211), carried by the SK 2020
	// TSTs (testMIDTS.bdoc): the protected digest/signature algorithms
	// must match the SignerInfo's, as the collector enforces.
	oidAttrAlgorithmProtection = "1.2.840.113549.1.9.52"
)

// Validator validates TimeStampTokens against a supplied data value.
// Its checks mirror the TST validation the Estonian e-voting collector
// (the library's interop target; see the README "Verification"
// section) applies: token structure, TSTInfo version, message imprint
// over the supplied data, nonce, signed-attribute integrity, the CMS
// signature over them (RSA or ECDSA), and the signer certificate
// selected from the configured pool — plus, because this package is
// go-asice's own TST check, a chain check of the signer against the
// supplied roots and a KeyUsage/EKU time-stamping requirement (the
// TSA-certificate checks the collector's container verification
// applies).
type Validator struct {
	// Roots are the trusted root CAs the TSA certificate must chain
	// to. At least one is required.
	Roots []*x509.Certificate
	// Intermediates are optional intermediate CAs for the chain.
	Intermediates []*x509.Certificate
	// TSTSigners is the configured TSA-signing certificate pool; the
	// SignerInfo identifies the signing certificate among these (the
	// model the collector's TSP configuration uses). At least one is
	// required.
	TSTSigners []*x509.Certificate

	// DigestModule computes message digests by hash algorithm OID
	// (the message imprint, the messageDigest signed attribute, the
	// signingCert(ingCertificateV2) certificate hash). Required.
	DigestModule tcrypto.DigestModule
	// SignatureVerifierModule verifies the CMS SignerInfo signature.
	// Required.
	SignatureVerifierModule tcrypto.SignatureVerifierModule
	// ChainModule verifies the TSA signing certificate chain (required
	// for Check; the client's checkTokenBody path does not chain the
	// signer).
	ChainModule tcrypto.CertificateChainModule

	// MaxAge is the maximum allowed now - genTime (default
	// DefaultMaxAge = 1 minute). Zero means DefaultMaxAge.
	MaxAge time.Duration
	// MaxSkew is the maximum allowed genTime - now (default
	// DefaultMaxSkew = 2 seconds). Zero means DefaultMaxSkew.
	MaxSkew time.Duration
}

// CheckOptions configures a Check call.
type CheckOptions struct {
	// Nonce, when non-nil, must equal the TST's nonce (RFC 3161: a
	// nonce present in the request MUST be present and equal in the
	// response).
	Nonce *big.Int
	// FreshnessCheck enables the genTime age/skew check against Now.
	// Stored-token checks (a TST embedded long ago in a container,
	// the collector's offline TST verification path) leave it false.
	FreshnessCheck bool
	// Now is the reference time for FreshnessCheck.
	Now time.Time
}

// Check validates token over the exact data and returns the token's
// generation time. A nil error means the token is a valid time-stamp
// over data: it was signed by a configured TSA signer whose
// certificate chains to Roots, and its message imprint is the digest
// of data.
func (v *Validator) Check(token, data []byte, opts CheckOptions) (time.Time, error) {
	maxAge := v.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	maxSkew := v.MaxSkew
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}
	if len(v.Roots) == 0 {
		return time.Time{}, errors.New("tsa: no roots configured")
	}
	if len(v.TSTSigners) == 0 {
		return time.Time{}, errors.New("tsa: no TSA signers configured")
	}
	if v.DigestModule == nil || v.SignatureVerifierModule == nil || v.ChainModule == nil {
		return time.Time{}, errors.New("tsa: Validator requires the crypto modules (DigestModule, SignatureVerifierModule, ChainModule)")
	}

	tsToken, err := Parse(token)
	if err != nil {
		return time.Time{}, err
	}
	info := tsToken.Content.EncapContentInfo.TSTInfo

	// TSTInfo version must be 1: the only version RFC 3161 defines
	// (the collector enforces this too).
	if info.Version != 1 {
		return time.Time{}, fmt.Errorf("tsa: TSTInfo version %d, want 1", info.Version)
	}

	// The message imprint must be a digest of the supplied data
	// (relaxed from the exact request match the collector requires —
	// but the imprint must equal the digest of data).
	calculated, err := v.DigestModule.GetDigestFunc(info.MessageImprint.HashAlgorithm.Algorithm)(data)
	if err != nil {
		return time.Time{}, fmt.Errorf("tsa: message imprint: %w", err)
	}
	if !bytes.Equal(info.MessageImprint.HashedMessage, calculated) {
		return time.Time{}, errors.New("tsa: message imprint does not match the digest of the supplied data")
	}

	// RFC 3161: a nonce in the request MUST be present and equal in
	// the response.
	if opts.Nonce != nil {
		if info.Nonce == nil {
			return time.Time{}, errors.New("tsa: nonce requested but missing from the TST")
		}
		if info.Nonce.Cmp(opts.Nonce) != 0 {
			return time.Time{}, fmt.Errorf("tsa: nonce mismatch: token has %s, want %s", info.Nonce, opts.Nonce)
		}
	}

	if opts.FreshnessCheck {
		if err := checkGenTime(opts.Now, info.GenTime, info.Accuracy, maxAge, maxSkew); err != nil {
			return time.Time{}, err
		}
	}

	// The token must be a single-Signer SignedData
	// (the check the collector's TST validation applies) whose signer
	// is a configured certificate included in the token, with intact
	// signed attributes and a valid CMS signature over them.
	if err := v.checkSignedData(tsToken, info.GenTime); err != nil {
		return time.Time{}, err
	}

	// Chain + purpose checks on the signing certificate (the TSA
	// checks the collector's container verification applies).
	if err := v.checkSignerChain(tsToken, info.GenTime); err != nil {
		return time.Time{}, err
	}
	return info.GenTime, nil
}

// checkGenTime applies the genTime freshness check the collector's
// TSP client applies: now - genTime + accuracy <= MaxAge and genTime
// <= now + MaxSkew - accuracy.
func checkGenTime(now, gen time.Time, acc Accuracy, maxAge, maxSkew time.Duration) error {
	accuracy := time.Duration(acc.Seconds)*time.Second +
		time.Duration(acc.Millis)*time.Millisecond +
		time.Duration(acc.Micros)*time.Microsecond

	if age := now.Sub(gen) + accuracy; age > maxAge {
		return fmt.Errorf("tsa: timestamp too old: genTime %s is %s before now %s (max %s)",
			gen.UTC().Format(time.RFC3339), age, now.UTC().Format(time.RFC3339), maxAge)
	}
	if gen.After(now.Add(maxSkew - accuracy)) {
		return fmt.Errorf("tsa: timestamp set in the future: genTime %s is after now %s + %s",
			gen.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), maxSkew)
	}
	return nil
}

// checkSignedData mirrors the collector's SignedData validation:
// content type, version 3, exactly one SignerInfo, signer
// identification from the configured pool, the signer certificate
// included in the token, signed attributes and the CMS signature over
// them.
func (v *Validator) checkSignedData(tsToken *TSToken, gen time.Time) error {
	if !tsToken.ContentType.Equal(OidSignedData) {
		return fmt.Errorf("tsa: token content type %s, want id-signedData", tsToken.ContentType)
	}
	sd := tsToken.Content
	if sd.Version != 3 {
		return fmt.Errorf("tsa: SignedData version %d, want 3 (non id-data content)", sd.Version)
	}
	if len(sd.SignerInfos) != 1 {
		return fmt.Errorf("tsa: SignedData has %d SignerInfo entries, want 1", len(sd.SignerInfos))
	}
	sInfo := sd.SignerInfos[0]

	cert, err := findSignerCert(sInfo, v.TSTSigners)
	if err != nil {
		return fmt.Errorf("tsa: untrusted signing certificate: %w", err)
	}

	var included bool
	for _, tc := range sd.Certificates {
		if bytes.Equal(tc.Raw, cert.Raw) {
			included = true
			break
		}
	}
	if !included {
		return fmt.Errorf("tsa: signing certificate %s is not included in the token", cert.Subject.CommonName)
	}

	if err := v.checkSignedAttributes(sInfo, sd.EncapContentInfo, gen, cert); err != nil {
		return fmt.Errorf("tsa: signed attribute check failed: %w", err)
	}
	if err := v.checkSignature(sInfo, cert); err != nil {
		return fmt.Errorf("tsa: signature check failed: %w", err)
	}
	return nil
}

// checkSignedAttributes mirrors the collector's signed-attribute
// validation: every attribute value must be a one-entry SET,
// attributes must not duplicate and must be one of the known CMS
// attributes, contentType/messageDigest/signingTime must be present
// and consistent with the token, and the
// signingCert(ingCertificateV2) attribute must identify the signer.
func (v *Validator) checkSignedAttributes(sInfo SignerInfo, encap TSTContentInfo, gen time.Time, signer *x509.Certificate) error {
	attrMap := make(map[string]bool)
	for _, attr := range sInfo.SignedAttrs {
		if attrMap[attr.AttrType.String()] {
			return fmt.Errorf("duplicate signed attribute %s", attr.AttrType)
		}
		attrMap[attr.AttrType.String()] = true

		if attr.attrValueTag != 49 {
			return fmt.Errorf("signed attribute %s value is not a SET (tag 0x%02x)", attr.AttrType, attr.attrValueTag)
		}
		value := attr.AttrValue

		switch attr.AttrType.String() {
		case oidAttrContentType:
			if err := checkAttrContentType(value, encap.EContentType); err != nil {
				return err
			}
		case oidAttrMessageDigest:
			if err := v.checkAttrMessageDigest(value, sInfo.DigestAlgorithm, encap.EContent); err != nil {
				return err
			}
		case oidAttrSigningTime:
			if err := checkAttrSigningTime(value, gen); err != nil {
				return err
			}
		case oidAttrSigningCert, oidAttrSigningCertV2:
			if err := v.checkAttrSigningCert(value, signer, attr.AttrType.String() == oidAttrSigningCertV2); err != nil {
				return err
			}
		case oidAttrAlgorithmProtection:
			if err := checkAlgorithmProtection(value, sInfo); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown signed attribute %s", attr.AttrType)
		}
	}
	if !attrMap[oidAttrContentType] {
		return errors.New("signed attribute contentType is missing")
	}
	if !attrMap[oidAttrMessageDigest] {
		return errors.New("signed attribute messageDigest is missing")
	}
	if !attrMap[oidAttrSigningTime] {
		return errors.New("signed attribute signingTime is missing")
	}
	if !attrMap[oidAttrSigningCert] && !attrMap[oidAttrSigningCertV2] {
		return errors.New("signed attribute signingCert(ingCertificateV2) is missing")
	}
	return nil
}

func checkAttrContentType(value []byte, encapType asn1.ObjectIdentifier) error {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(value, &oid)
	if err != nil {
		return fmt.Errorf("signed attribute contentType: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("signed attribute contentType has %d trailing bytes", len(rest))
	}
	if !oid.Equal(encapType) {
		return fmt.Errorf("signed attribute contentType %s != token content type %s", oid, encapType)
	}
	return nil
}

func (v *Validator) checkAttrMessageDigest(value []byte, alg pkix.AlgorithmIdentifier, encap []byte) error {
	var digest []byte
	rest, err := asn1.Unmarshal(value, &digest)
	if err != nil {
		return fmt.Errorf("signed attribute messageDigest: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("signed attribute messageDigest has %d trailing bytes", len(rest))
	}
	calculated, err := v.DigestModule.GetDigestFunc(alg.Algorithm)(encap)
	if err != nil {
		return fmt.Errorf("signed attribute messageDigest: %w", err)
	}
	if !bytes.Equal(digest, calculated) {
		return errors.New("signed attribute messageDigest does not match the digest of the token content (TSTInfo)")
	}
	return nil
}

func checkAttrSigningTime(value []byte, gen time.Time) error {
	var t time.Time
	rest, err := asn1.Unmarshal(value, &t)
	if err != nil {
		return fmt.Errorf("signed attribute signingTime: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("signed attribute signingTime has %d trailing bytes", len(rest))
	}
	if !t.Equal(gen) {
		return fmt.Errorf("signed attribute signingTime %s differs from TST genTime %s", t.UTC(), gen.UTC())
	}
	return nil
}

// checkAttrSigningCert verifies a signingCert (RFC 5652: SHA-1, no
// algorithm) or signingCertificateV2 (RFC 5755: SHA-256 default or
// explicit) attribute against the signer certificate, mirroring the
// collector's signingCert validation.
func (v *Validator) checkAttrSigningCert(value []byte, signer *x509.Certificate, v2 bool) error {
	var sc signingCertificateV2
	rest, err := asn1.Unmarshal(value, &sc)
	if err != nil {
		return fmt.Errorf("signed attribute signingCert: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("signed attribute signingCert has %d trailing bytes", len(rest))
	}
	if len(sc.Certs) == 0 {
		return errors.New("signed attribute signingCert has no certificate identifiers")
	}
	ess := sc.Certs[0] // the first MUST identify the signing certificate

	var chashOID asn1.ObjectIdentifier
	if v2 {
		chashOID = oidSHA256
		if len(ess.HashAlgorithm.Algorithm) > 0 {
			chashOID = ess.HashAlgorithm.Algorithm
		}
	} else {
		chashOID = oidSHA1
		if len(ess.HashAlgorithm.Algorithm) > 0 {
			return fmt.Errorf("signed attribute signingCert: digest algorithm %s must be absent",
				ess.HashAlgorithm.Algorithm)
		}
	}
	certHash, err := v.DigestModule.GetDigestFunc(chashOID)(signer.Raw)
	if err != nil {
		return fmt.Errorf("signed attribute signingCert: %w", err)
	}
	if !bytes.Equal(certHash, ess.CertHash) {
		return errors.New("signed attribute signingCert certificate hash does not match the signer")
	}

	if len(ess.IssuerSerial.FullBytes) > 0 {
		name, serial, err := findIssuerSerial(ess.IssuerSerial.FullBytes)
		if err != nil {
			return err
		}
		if !certHasIssuerSerial(signer, name, serial) {
			return errors.New("signed attribute signingCert issuer/serial does not match the signer")
		}
	}
	return nil
}

// findIssuerSerial extracts the issuer Name and serial number from an
// issuerSerial element. It accepts the RFC 5755 layout used by the
// fixture TST —
//
//	[0] { SEQUENCE { [4] Name, INTEGER } }
//
// — and over-nested variants where the GeneralName is wrapped extra
// times. The Name is the innermost SEQUENCE whose content starts with
// an RDN SET (0x31); the serial is the single INTEGER in the tree.
func findIssuerSerial(der []byte) (name pkix.RDNSequence, serial *big.Int, err error) {
	var root asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &root); err != nil {
		return nil, nil, fmt.Errorf("tsa: malformed issuerSerial element: %w", err)
	} else if len(rest) > 0 {
		return nil, nil, errors.New("tsa: malformed issuerSerial element (trailing bytes)")
	}
	var foundName *pkix.RDNSequence
	var intCount int
	var foundSerial *big.Int
	var walk func(v asn1.RawValue) error
	walk = func(v asn1.RawValue) error {
		if !v.IsCompound {
			if v.Class == 0 && v.Tag == 2 {
				intCount++
				foundSerial = new(big.Int).SetBytes(v.Bytes)
			}
			return nil
		}
		if v.Class == 0 && v.Tag == 16 && foundName == nil && len(v.Bytes) >= 2 && v.Bytes[0] == 0x31 {
			var rdn pkix.RDNSequence
			if _, err := asn1.Unmarshal(v.FullBytes, &rdn); err != nil {
				return fmt.Errorf("tsa: malformed issuer name in issuerSerial: %w", err)
			}
			foundName = &rdn
			return nil
		}
		children, err := rawChildren(v)
		if err != nil {
			return fmt.Errorf("tsa: malformed issuerSerial structure: %w", err)
		}
		for _, ch := range children {
			if err := walk(ch); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, nil, err
	}
	if foundName == nil {
		return nil, nil, errors.New("tsa: no issuer name found in issuerSerial")
	}
	if intCount != 1 {
		return nil, nil, fmt.Errorf("tsa: expected exactly 1 serial number in issuerSerial, found %d", intCount)
	}
	return *foundName, foundSerial, nil
}

// rawChildren returns the direct child TLVs of a compound ASN.1
// element.
func rawChildren(v asn1.RawValue) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	rest := v.Bytes
	for len(rest) > 0 {
		var c asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// checkSignature mirrors the collector's TST signature check: the
// signature algorithm must be supported and paired with its digest,
// and the signature must verify over the signed attributes re-encoded
// as a SET OF (the CMS encoding).
func (v *Validator) checkSignature(sInfo SignerInfo, cert *x509.Certificate) error {
	if len(sInfo.Signature) == 0 {
		return errors.New("SignerInfo has no signature")
	}
	wantDigest, ok := signatureDigestOIDs[sInfo.SignatureAlgorithm.Algorithm.String()]
	if !ok || !wantDigest.Equal(sInfo.DigestAlgorithm.Algorithm) {
		return fmt.Errorf("signature algorithm %s not paired with digest algorithm %s",
			sInfo.SignatureAlgorithm.Algorithm, sInfo.DigestAlgorithm.Algorithm)
	}

	// Re-encode the signed attributes as the CMS signer did: the
	// attribute SEQUENCEs wrapped in a SET OF (0x31). Go preserves
	// slice order, so the encoding is byte-identical to the wire
	// bytes (the attribute values are SET OF, kept from Parse).
	raw := make([]cmsSignedAttribute, 0, len(sInfo.SignedAttrs))
	for _, a := range sInfo.SignedAttrs {
		raw = append(raw, cmsSignedAttribute{
			AttrType:  a.AttrType,
			AttrValue: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: a.AttrValue},
		})
	}
	attrsDER, err := asn1.Marshal(raw)
	if err != nil {
		return fmt.Errorf("re-encode signed attributes: %w", err)
	}
	attrsDER[0] = 49 // SET OF

	if err := v.SignatureVerifierModule.VerifySignature(cert, sInfo.SignatureAlgorithm.Algorithm, attrsDER, sInfo.Signature); err != nil {
		return fmt.Errorf("signature does not verify: %w", err)
	}
	return nil
}

// checkSignerChain verifies the signing certificate against the
// configured roots (at the TST genTime) through the chain module and
// enforces the TSA purpose bits the Estonian e-voting collector's
// container verification requires: KeyUsage digitalSignature and EKU
// time-stamping (the purpose bits are checked by the standard module).
func (v *Validator) checkSignerChain(tsToken *TSToken, gen time.Time) error {
	sInfo := tsToken.Content.SignerInfos[0]
	cert, err := findSignerCert(sInfo, v.TSTSigners)
	if err != nil {
		return err
	}
	return v.ChainModule.VerifyChain(cert, v.Roots, v.Intermediates, gen)
}

// signingCertificateV2 is the signingCertificateV2 structure the
// interop contract with the Estonian e-voting collector unmarshals;
// the .12 and .47 signed attributes share it. Go's asn1 cannot decode
// pointer fields, so plain value types are used directly and the
// issuerSerial element is kept raw — the fixture TST uses the RFC 5755
// layout while some TST builders over-nest the GeneralName, so the
// name and serial are extracted leniently (findIssuerSerial).
type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

// cmsAlgorithmProtection is the CMSAlgorithmProtection structure of
// RFC 6211 (the id-cms-algorithmProtection signed attribute value):
// SEQUENCE { digestAlgorithm [0] IMPLICIT, signatureAlgorithm [1]
// IMPLICIT }.
type cmsAlgorithmProtection struct {
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:"tag:1"`
}

// checkAlgorithmProtection mirrors the collector's
// algorithm-protection check: the attribute value must decode cleanly
// and its protected digest and signature algorithms must equal the
// SignerInfo's own.
func checkAlgorithmProtection(value []byte, sInfo SignerInfo) error {
	var protection cmsAlgorithmProtection
	rest, err := asn1.Unmarshal(value, &protection)
	if err != nil {
		return fmt.Errorf("signed attribute algorithmProtection: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("signed attribute algorithmProtection has %d trailing bytes", len(rest))
	}
	if !algorithmIdentifierEqual(sInfo.DigestAlgorithm, protection.DigestAlgorithm) {
		return fmt.Errorf("signed attribute algorithmProtection digest algorithm %s differs from the SignerInfo digest algorithm %s",
			protection.DigestAlgorithm.Algorithm, sInfo.DigestAlgorithm.Algorithm)
	}
	if !algorithmIdentifierEqual(sInfo.SignatureAlgorithm, protection.SignatureAlgorithm) {
		return fmt.Errorf("signed attribute algorithmProtection signature algorithm %s differs from the SignerInfo signature algorithm %s",
			protection.SignatureAlgorithm.Algorithm, sInfo.SignatureAlgorithm.Algorithm)
	}
	return nil
}

// algorithmIdentifierEqual compares two AlgorithmIdentifiers the way
// the collector's algorithm-identifier comparison does: equal OIDs and
// equal DER parameter encodings (absent parameters on both sides).
func algorithmIdentifierEqual(a, b pkix.AlgorithmIdentifier) bool {
	if !a.Algorithm.Equal(b.Algorithm) {
		return false
	}
	derA, errA := asn1.Marshal(a.Parameters)
	derB, errB := asn1.Marshal(b.Parameters)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(derA, derB)
}
