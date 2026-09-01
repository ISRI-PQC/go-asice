// Package testutil is a test-SUPPORT package: a hermetic (wall-clock-free)
// test PKI plus the OCSP and time-stamp token generation that the repo's
// tests and the companion interop acceptance harness (module
// the companion asice-compat harness) use to build ASiC-E containers and the TST/OCSP
// artifacts embedded in them. It is deliberately NOT internal so the
// companion harness can import it.
//
// The PKI models the SK test PKI shape of the ASiC-E interop fixtures
// (see test/samples/README.md for the hermetic fixtures this repo
// generates):
//
//   - root CA (RSA-2048), self-signed
//   - issuer CA (RSA-2048), intermediate signed by the root
//   - signer leaf (ECDSA P-256) with critical KeyUsage ContentCommitment,
//     as the interop contract with the Estonian e-voting collector
//     (the library's interop target; see the README) requires — its
//     signer-certificate verification rejects certs without the bit
//   - second signer leaf (ECDSA P-256, same template, same issuer), for
//     multi-signature (S0/S1) containers where each signature document
//     must carry a distinct signer certificate
//   - OCSP responder leaf (RSA-2048, issued by the issuer CA) with critical
//     KU DigitalSignature and critical EKU OCSPSigning. RSA because
//     the collector's OCSP verification accepts only the
//     SHA-256/384/512-with-RSA response-signature variants
//   - TSA leaf (ECDSA P-256, issued by the root — like the fixture TSA cert
//     "DEMO of SK TSA 2014") with critical KU DigitalSignature|NonRepudiation
//     and critical EKU TimeStamping
//
// OCSP responses (RFC 6960) and time-stamp tokens (RFC 3161/CMS) are built
// with stdlib ASN.1. Produced times are always injected by the caller:
// OCSPResponse(producedAt) and TimeStampToken(data, TSTOptions{GenTime}).
// For a TS-profile container the collector's time-window check
// (ADR 0003) requires
//
//	genTime <= producedAt <= genTime+TSDelayTime
//
// (producedAt.Sub(genTime) in [0, tsdelay]). The
// fixture testEIDTS.bdoc uses IDENTICAL times for both; pass the same time
// to both generators (or a GenTime earlier than producedAt by less than
// TSDelayTime).
package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Fixed 16-byte serial numbers modeled on the SK test PKI (16-byte serials).
var (
	serialRoot      = new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	serialIssuer    = new(big.Int).SetBytes([]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	serialSigner    = new(big.Int).SetBytes([]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48})
	serialSigner2   = new(big.Int).SetBytes([]byte{81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96})
	serialResponder = new(big.Int).SetBytes([]byte{49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64})
	serialTSA       = new(big.Int).SetBytes([]byte{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80})
)

// defaultValidity is applied when Options.NotAfter is zero.
const defaultValidity = 10 * 365 * 24 * time.Hour

var errZeroTime = errors.New("testutil: required time is zero; inject an explicit time (no wall-clock defaults)")

// Well-known OIDs.
var (
	oidOCSPNoCheck     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 3}
	oidEKUOCSPSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidEKUTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidCRLDistribution = asn1.ObjectIdentifier{2, 5, 29, 31}
)

// Placeholder AIA/CRL URLs. The collector never fetches them (offline
// verification only); they exist so the generated certs look like the SK
// test certs.
const (
	aiaOCSPURL      = "http://localhost:8989/ocsp"
	aiaCAIssuersURL = "http://localhost:8989/ca.der.crt"
	crlURL          = "http://localhost:8989/crl"
)

// Options configures the generated certificates.
type Options struct {
	// Now is REQUIRED: the reference point of every generated artifact.
	// The zero value is rejected so tests can never depend on the wall
	// clock.
	Now time.Time

	// NotBefore/NotAfter apply to every certificate. Defaults:
	// Now.Add(-24*time.Hour) and Now.Add(defaultValidity).
	NotBefore time.Time
	NotAfter  time.Time
}

// Cert pairs a certificate with its key and both encodings.
type Cert struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	// DER is the certificate's DER encoding; PEM is its PEM block
	// (what the trust YAMLs of the acceptance harness expect).
	DER []byte
	PEM []byte
}

// PKI is a self-contained test certificate hierarchy.
type PKI struct {
	Root          *Cert
	Issuer        *Cert
	Signer        *Cert
	Signer2       *Cert // second signer leaf (same template + issuer as Signer), for multi-signature containers
	OCSPResponder *Cert
	TSA           *Cert
}

// certTemplate is the internal role description for one generated
// certificate.
type certTemplate struct {
	subject  pkix.Name
	serial   *big.Int
	keyUsage x509.KeyUsage
	extraEKU []asn1.ObjectIdentifier // non-standard EKU OIDs (none used)
	isCA     bool
	hasAIA   bool // signer: OCSP + caIssuers access descriptors
	noCheck  bool // responder: id-ad-ocsp-nocheck extension
	hasCRLDP bool // TSA: CRL distribution point
}

// NewPKI generates a fresh test PKI per Options. All times are taken from
// Options; nothing else reads the wall clock. Keys are random per call
// (time-determinism, not byte-determinism, is the hermeticity requirement).
func NewPKI(opts Options) (*PKI, error) {
	if opts.Now.IsZero() {
		return nil, errZeroTime
	}
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = opts.Now.Add(-24 * time.Hour)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = opts.Now.Add(defaultValidity)
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("testutil: NotAfter %s must be after NotBefore %s", notAfter, notBefore)
	}

	// Subjects model the SK test PKI inside the test/samples fixtures.
	rootName := pkix.Name{
		Country:            []string{"EE"},
		Organization:       []string{"ASICE Test Solutions AS"},
		OrganizationalUnit: []string{"ASICE Test PKI"},
		CommonName:         "TEST of ASICE Root CA",
	}
	issuerName := pkix.Name{
		Country:            []string{"EE"},
		Organization:       []string{"ASICE Test Solutions AS"},
		OrganizationalUnit: []string{"ASICE Test PKI"},
		CommonName:         "TEST of ASICE Issuer CA 2025",
	}
	signerName := pkix.Name{
		Country:      []string{"EE"},
		Organization: []string{"ASICE Test Solutions AS"},
		CommonName:   "TEST of ASICE EID2025",
	}
	signer2Name := pkix.Name{
		Country:      []string{"EE"},
		Organization: []string{"ASICE Test Solutions AS"},
		CommonName:   "TEST of ASICE EID2025-2",
	}
	responderName := pkix.Name{
		Country:            []string{"EE"},
		Organization:       []string{"ASICE Test Solutions AS"},
		OrganizationalUnit: []string{"OCSP"},
		CommonName:         "TEST of ASICE OCSP RESPONDER 2025",
	}
	tsaName := pkix.Name{
		Country:            []string{"EE"},
		Organization:       []string{"ASICE Test Solutions AS"},
		OrganizationalUnit: []string{"TSA"},
		CommonName:         "TEST of ASICE TSA 2025",
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate issuer key: %w", err)
	}
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signer key: %w", err)
	}
	signer2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signer2 key: %w", err)
	}
	responderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate responder key: %w", err)
	}
	tsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate TSA key: %w", err)
	}

	root, err := newSelfSignedRoot(&certTemplate{
		subject:  rootName,
		serial:   serialRoot,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		isCA:     true,
	}, notBefore, notAfter, rootKey)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}

	issuer, err := newCert(&certTemplate{
		subject:  issuerName,
		serial:   serialIssuer,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		isCA:     true,
	}, notBefore, notAfter, root.Certificate, rootKey, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}

	signer, err := newCert(&certTemplate{
		subject:  signerName,
		serial:   serialSigner,
		keyUsage: x509.KeyUsageContentCommitment, // required by the collector; the fixture signer carries exactly this bit (critical)
		hasAIA:   true,
	}, notBefore, notAfter, issuer.Certificate, issuerKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}

	signer2, err := newCert(&certTemplate{
		subject:  signer2Name,
		serial:   serialSigner2,
		keyUsage: x509.KeyUsageContentCommitment, // same template as the signer leaf
		hasAIA:   true,
	}, notBefore, notAfter, issuer.Certificate, issuerKey, signer2Key)
	if err != nil {
		return nil, fmt.Errorf("signer2: %w", err)
	}

	responder, err := newCert(&certTemplate{
		subject:  responderName,
		serial:   serialResponder,
		keyUsage: x509.KeyUsageDigitalSignature,
		extraEKU: []asn1.ObjectIdentifier{oidEKUOCSPSigning},
		noCheck:  true,
	}, notBefore, notAfter, issuer.Certificate, issuerKey, responderKey)
	if err != nil {
		return nil, fmt.Errorf("ocsp responder: %w", err)
	}

	tsa, err := newCert(&certTemplate{
		subject:  tsaName,
		serial:   serialTSA,
		keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		extraEKU: []asn1.ObjectIdentifier{oidEKUTimeStamping},
		hasCRLDP: true,
	}, notBefore, notAfter, root.Certificate, rootKey, tsaKey) // like the fixture: the TSA cert is issued by the ROOT
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}

	return &PKI{Root: root, Issuer: issuer, Signer: signer, Signer2: signer2, OCSPResponder: responder, TSA: tsa}, nil
}

// buildCertTemplate fills an x509 template from the role description.
// SubjectKeyId is set explicitly (binary SHA-1 of the public key BIT
// STRING); Go then copies the parent's SubjectKeyId into AuthorityKeyId
// automatically.
func buildCertTemplate(role *certTemplate, notBefore, notAfter time.Time, pub crypto.PublicKey) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          role.serial,
		Subject:               role.subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              role.keyUsage,
		SubjectKeyId:          subjectKeyID(pub),
		BasicConstraintsValid: true,
		IsCA:                  role.isCA,
	}
	if role.extraEKU != nil {
		tmpl.UnknownExtKeyUsage = role.extraEKU
	}
	if role.hasAIA {
		// The collector never fetches these URLs (offline verification);
		// the fixture signer carries the same two descriptors.
		tmpl.OCSPServer = []string{aiaOCSPURL}
		tmpl.IssuingCertificateURL = []string{aiaCAIssuersURL}
	}
	if role.hasCRLDP {
		tmpl.CRLDistributionPoints = []string{crlURL}
	}
	if role.noCheck {
		// id-ad-ocsp-nocheck: empty extension, like the fixture responder.
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidOCSPNoCheck, Value: nil}}
	}
	return tmpl
}

// newCert signs a role (leaf) certificate against parent using parentSigner.
// Go's x509.CreateCertificate requires the PARENT's private key as the
// signing key; leafKey is the subject's own key (stored on the Cert).
func newCert(role *certTemplate, notBefore, notAfter time.Time, parent *x509.Certificate, parentSigner, leafKey crypto.Signer) (*Cert, error) {
	tmpl := buildCertTemplate(role, notBefore, notAfter, leafKey.Public())
	return signCert(tmpl, parent, leafKey.Public(), parentSigner, leafKey)
}

// newSelfSignedRoot signs the root against itself.
func newSelfSignedRoot(role *certTemplate, notBefore, notAfter time.Time, priv crypto.Signer) (*Cert, error) {
	tmpl := buildCertTemplate(role, notBefore, notAfter, priv.Public())
	// Self-signed: the authority key identifier equals its own SKI.
	tmpl.AuthorityKeyId = subjectKeyID(priv.Public())
	return signCert(tmpl, tmpl, priv.Public(), priv, priv)
}

func signCert(tmpl *x509.Certificate, parent *x509.Certificate, leafPub crypto.PublicKey, signer, leafKey crypto.Signer) (*Cert, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, leafPub, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated cert: %w", err)
	}
	return &Cert{
		Certificate: cert,
		PrivateKey:  leafKey,
		DER:         der,
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// subjectKeyID is the SHA-1 of the public key BIT STRING (RFC 5280
// 4.2.1.2), computed from the PKIX-marshaled public key.
func subjectKeyID(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("testutil: marshal public key: %v", err))
	}
	var spki struct {
		Alg pkix.AlgorithmIdentifier
		Key asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		panic(fmt.Sprintf("testutil: unmarshal public key: %v", err))
	}
	h := sha1.Sum(spki.Key.Bytes)
	return h[:]
}
