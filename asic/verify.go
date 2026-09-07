// Self-verification of ASiC-E containers: the verification core of
// asic.Verify (T8a BES core + T8b TS profile). It mirrors the check
// order of the Estonian e-voting collector's container verification —
// container structure,
// then per signature: XML shape, signer certificate, signing time,
// certificate chain, signature value (C14N 1.1 of SignedInfo),
// references (file digests + SignedProperties digest),
// QualifyingProperties target, and signed-property consistency. The TS
// profile adds, per signature: the UnsignedProperties shape, the TST
// check (checkTimestamp: SHA-256/384/512 imprint over the C14N 1.1
// ds:SignatureValue element + CMS verification, tsa.Validator), the
// embedded OCSP response check (checkOCSP: certID, responder, signature,
// producedAt/thisUpdate window), and the TSDelayTime 60s bound between
// OCSP producedAt and TST genTime (ADR 0003).

package asic

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	asiccrypto "github.com/isri-pqc/go-asice/asic/crypto"
	xcrypto "github.com/isri-pqc/go-xmlsig/crypto"
)

// Profile selects the ASiC-E verification profile.
type Profile int

// Verification profiles (the collector's verification profiles).
const (
	// ProfileBES verifies the BES core: container structure, file
	// digests, C14N 1.1, signature cryptography, certificate chain,
	// and signed properties.
	ProfileBES Profile = iota

	// ProfileTS is the BES core plus the TS profile checks:
	// the xades:UnsignedProperties shape (TST + embedded OCSP
	// response + certificates), the TST verification against the
	// C14N 1.1 ds:SignatureValue imprint, the OCSP response
	// verification, and the TSDelayTime 60s bound (ADR 0003).
	// Verify additionally requires the TS crypto modules
	// (VerifyOptions.OCSPModule + VerifyOptions.TSTVerifier).
	ProfileTS
)

// VerifyOptions configures a Verify call.
type VerifyOptions struct {
	// Profile selects the verification profile; zero means BES.
	Profile Profile

	// RootsPEM holds one or more PEM-encoded CERTIFICATE blocks — the
	// trust anchors a signer certificate must chain to.
	RootsPEM []byte

	// IntermediatesPEM holds one or more PEM-encoded CERTIFICATE
	// blocks — intermediate CAs allowed in the chain.
	IntermediatesPEM []byte

	// OCSPRespondersPEM holds one or more PEM-encoded CERTIFICATE
	// blocks — the configured OCSP responders (the trust YAML
	// ocsp.responders list). Optional for ProfileTS: when the embedded
	// responder certificate is not in the list, the response is
	// verified against the signer's issuer certificate instead (the
	// collector's issuer fallback).
	OCSPRespondersPEM []byte

	// --- Crypto modules (ADR 0004) ---

	// DigestModule computes the reference digests (data files,
	// SignedProperties). Required.
	DigestModule xcrypto.XMLDigestModule
	// VerifierModule verifies the XML-DSig signature value against the
	// KeyInfo certificate. Required.
	VerifierModule xcrypto.XMLSignatureVerifierModule
	// ChainModule verifies the signer certificate chain (the collector's
	// semantics). Required.
	ChainModule asiccrypto.CertificateChainModule
	// OCSPModule verifies the embedded OCSP response. Required for
	// ProfileTS.
	OCSPModule asiccrypto.OCSPVerifierModule
	// TSTVerifier verifies the embedded RFC 3161 TST (the TSA signer
	// pool is configured on the verifier). Required for ProfileTS.
	TSTVerifier asiccrypto.TSTVerifierModule
}

// Report is the verdict of a Verify call.
type Report struct {
	// Profile is the profile the container was verified under.
	Profile Profile

	// OK is the overall verdict: true only when the container
	// structure is valid and every signature passes all checks.
	OK bool

	// DataFiles lists the container data file names (empty when the
	// container structure is invalid).
	DataFiles []string

	// Signatures holds one entry per signature file, in container
	// order (empty when the container structure is invalid).
	Signatures []SignatureReport

	// Errors lists container-level actionable failures. When
	// non-empty the container is rejected and Signatures is empty.
	Errors []string
}

// SignatureReport is the verdict for one signature file.
type SignatureReport struct {
	// ID is the ds:Signature Id (e.g. "S0").
	ID string

	// Signer is the signer certificate's subject (common name if set,
	// else the full distinguished name).
	Signer string

	// SigningTime is the xades:SigningTime parsed from the
	// signature's SignedProperties (zero when missing or invalid).
	SigningTime time.Time

	// OK is true only when every BES check passed for this signature.
	OK bool

	// Errors lists the actionable failures of this signature.
	Errors []string
}

// Verify verifies the ASiC-E container at containerPath under opts and
// returns the verdict.
//
// A non-nil error means verification could not start: the container
// file is unreadable, the supplied trust certificates do not parse, or
// the required crypto modules are not supplied (a TS-profile
// verification also requires OCSPModule and TSTVerifier).
// Container and signature failures are verdicts, not errors: they come
// back in the Report with OK == false and actionable messages in
// Report.Errors or the per-signature entries.
func Verify(containerPath string, opts VerifyOptions) (*Report, error) {
	roots, err := ParsePEMCerts(opts.RootsPEM)
	if err != nil {
		return nil, fmt.Errorf("asic: roots: %w", err)
	}
	if len(roots) == 0 {
		return nil, errors.New("asic: no trust anchor certificates supplied (RootsPEM)")
	}
	intermediates, err := ParsePEMCerts(opts.IntermediatesPEM)
	if err != nil {
		return nil, fmt.Errorf("asic: intermediates: %w", err)
	}
	if opts.DigestModule == nil || opts.VerifierModule == nil || opts.ChainModule == nil {
		return nil, errors.New("asic: Verify requires the crypto modules (DigestModule, VerifierModule, ChainModule)")
	}
	var ts *tsContext
	if opts.Profile == ProfileTS {
		if opts.OCSPModule == nil || opts.TSTVerifier == nil {
			return nil, errors.New("asic: TS profile requires the TS crypto modules (OCSPModule, TSTVerifier)")
		}
		ocspResponders, err := ParsePEMCerts(opts.OCSPRespondersPEM)
		if err != nil {
			return nil, fmt.Errorf("asic: OCSP responders: %w", err)
		}
		ts = &tsContext{
			roots:          roots,
			intermediates:  intermediates,
			ocspResponders: ocspResponders,
			ocspModule:     opts.OCSPModule,
			tstVerifier:    opts.TSTVerifier,
		}
	}
	raw, err := os.ReadFile(containerPath)
	if err != nil {
		return nil, fmt.Errorf("asic: read container: %w", err)
	}
	return verifyContainer(raw, opts.Profile, &verifyModules{
		digest:        opts.DigestModule,
		verifier:      opts.VerifierModule,
		chain:         opts.ChainModule,
		roots:         roots,
		intermediates: intermediates,
	}, ts)
}

// tsContext carries the TS-profile input for the per-signature TS
// checks (nil when the profile is BES).
type tsContext struct {
	// roots and intermediates are the trust certificates used for the
	// OCSP issuer fallback.
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	// ocspResponders are the configured OCSP responder certificates
	// (the trust YAML ocsp.responders list).
	ocspResponders []*x509.Certificate
	// ocspModule verifies the embedded OCSP response (ADR 0004).
	ocspModule asiccrypto.OCSPVerifierModule
	// tstVerifier verifies the embedded TST over the C14N 1.1
	// ds:SignatureValue imprint (ADR 0004; the TSA signer pool is
	// configured on the verifier).
	tstVerifier asiccrypto.TSTVerifierModule
}

// verifyModules bundles the injected BES-level inputs for one Verify
// call: the trust certificates and the crypto modules (ADR 0004).
type verifyModules struct {
	// digest computes the reference digests (data files,
	// SignedProperties).
	digest xcrypto.XMLDigestModule
	// verifier verifies the XML-DSig signature value.
	verifier xcrypto.XMLSignatureVerifierModule
	// chain verifies the signer certificate chain (the collector's
	// semantics).
	chain asiccrypto.CertificateChainModule
	// roots are the trust anchors the signer must chain to.
	roots []*x509.Certificate
	// intermediates are the intermediate CAs of the signer chain.
	intermediates []*x509.Certificate
}

// verifyContainer runs the full verification (BES core, plus the TS
// profile checks when ts is non-nil) over container bytes.
func verifyContainer(raw []byte, profile Profile, m *verifyModules, ts *tsContext) (*Report, error) {
	report := &Report{Profile: profile}
	ctr, cerrs := openContainer(raw)
	if cerrs != nil {
		report.Errors = cerrs
		return report, nil
	}
	names := make([]string, 0, len(ctr.sigDocs))
	for name := range ctr.sigDocs {
		names = append(names, name)
	}
	sort.Strings(names)
	report.DataFiles = ctr.fileNames()
	for _, name := range names {
		rep := verifySignature(ctr, name, ctr.sigDocs[name], m, ts)
		report.Signatures = append(report.Signatures, *rep)
	}
	report.OK = true
	for i := range report.Signatures {
		report.OK = report.OK && report.Signatures[i].OK
	}
	return report, nil
}

// ParsePEMCerts extracts and parses every PEM-encoded CERTIFICATE block
// from b (in order). Non-certificate blocks are an error.
func ParsePEMCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := b
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("asic: unexpected PEM block type %q (want CERTIFICATE)", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("asic: parse certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// container is a structurally verified ASiC-E archive: the ODF manifest
// media types, the data files, and the signature file documents.
type container struct {
	// files maps data file names to content.
	files map[string][]byte
	// sigDocs maps signature file names (META-INF/signaturesN.xml) to
	// the raw document bytes.
	sigDocs map[string][]byte
	// manifest maps data file names to their ODF media type.
	manifest map[string]string
}

// fileNames returns the data file names sorted.
func (c *container) fileNames() []string {
	names := make([]string, 0, len(c.files))
	for name := range c.files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// sigFileRE matches the signature file names the collector's container
// open accepts (case-sensitive).
var sigFileRE = regexp.MustCompile(`^META-INF/[^/]*signatures[^/]*\.xml$`)

// maxEntryUncompressed bounds the uncompressed size of a single ZIP
// entry on the untrusted read path. A hostile .asice can carry a small
// high-compression entry that decompresses to gigabytes (a zip bomb);
// verification must reject it fast, not OOM, before any structural or
// cryptographic check runs. A var (not a const) so tests can shrink it.
var maxEntryUncompressed = int64(64 << 20) // 64 MiB per entry

// maxTotalUncompressed bounds the aggregate uncompressed size of all
// container entries on the untrusted read path (see
// maxEntryUncompressed). A var (not a const) so tests can shrink it.
var maxTotalUncompressed = int64(256 << 20) // 256 MiB total

// openContainer validates the container structure the way the
// Estonian e-voting collector's container open does (PLAN.md §1.1; the
// error strings mirror the collector's rejection taxonomy):
// stored "mimetype" magic entry with the exact ASiC-E content type,
// META-INF/manifest.xml, flat data files, signature files matching
// sigFileRE, and a manifest covering every data file. Entry and total
// uncompressed sizes are bounded by the zip-bomb limits below, so a
// hostile container is rejected fast instead of exhausting memory.
// Duplicate META-INF entry names are rejected the same way as the
// other duplicate names.
func openContainer(raw []byte) (*container, []string) {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, []string{"container is not a valid ZIP archive"}
	}
	entries := zr.File
	if len(entries) == 0 {
		return nil, []string{"container has no entries"}
	}

	// The first entry must be the stored "mimetype" magic file with
	// the exact ASiC-E content type (TS 102 918 §A.1; the collector's
	// first-entry magic check): local header at byte 0, no
	// data descriptor, no extra field, stored method, exact content.
	first := entries[0]
	if first.Name != MimeTypeFile {
		return nil, []string{"first entry is not the \"mimetype\" magic file"}
	}
	if first.Flags&0x0008 != 0 {
		return nil, []string{"mimetype entry must not use a data descriptor"}
	}
	if first.Method != zip.Store {
		return nil, []string{"mimetype entry must be stored (uncompressed)"}
	}
	if off, err := first.DataOffset(); err != nil || off != int64(30+len(MimeTypeFile)) {
		return nil, []string{"mimetype entry is not the local header at byte 0 with no extra field"}
	}
	mdata, err := readZipEntry(first, MimeTypeFile)
	if err != nil {
		return nil, []string{fmt.Sprintf("read mimetype entry: %v", err)}
	}
	if !bytes.Equal(mdata, []byte(MimeTypeContent)) {
		return nil, []string{fmt.Sprintf("mimetype content is %q, want %q", string(mdata), MimeTypeContent)}
	}

	ctr := &container{
		files:    make(map[string][]byte),
		sigDocs:  make(map[string][]byte),
		manifest: make(map[string]string),
	}
	var manifestDoc []byte
	manifestSeen := false
	totalUncompressed := int64(len(mdata))
	for _, ef := range entries[1:] {
		name := ef.Name
		data, err := readZipEntry(ef, name)
		totalUncompressed += int64(len(data))
		if totalUncompressed > maxTotalUncompressed {
			add("container exceeds the uncompressed size limit")
			break
		}
		switch {
		case name == MimeTypeFile:
			add("duplicate entry name %q", name)
		case name == ManifestFile:
			if err != nil {
				add("read %s: %v", name, err)
				break
			}
			if manifestSeen {
				add("duplicate entry name %q", name)
				break
			}
			manifestSeen = true
			manifestDoc = data
		case sigFileRE.MatchString(name):
			if err == nil {
				if _, ok := ctr.sigDocs[name]; ok {
					add("duplicate entry name %q", name)
					break
				}
				ctr.sigDocs[name] = data
			} else {
				add("read %s: %v", name, err)
			}
		case strings.HasPrefix(name, "META-INF/"):
			add("unknown META-INF entry %q", name)
		case strings.ContainsAny(name, "/\\"):
			add("data file %q is in a subfolder", name)
		default:
			if err != nil {
				add("read %s: %v", name, err)
				break
			}
			if _, ok := ctr.files[name]; ok {
				add("duplicate entry name %q", name)
				break
			}
			ctr.files[name] = data
		}
	}
	if manifestDoc == nil {
		add("missing %s", ManifestFile)
	}
	if len(ctr.files) == 0 {
		add("no data files")
	}
	if len(ctr.sigDocs) == 0 {
		add("no signature files")
	}
	if errs != nil {
		return nil, errs
	}
	if merrs := parseManifest(manifestDoc, ctr); merrs != nil {
		return nil, merrs
	}
	return ctr, nil
}

// readZipEntry returns the full content of a stored or deflated
// entry, bounded to maxEntryUncompressed bytes of uncompressed data:
// an entry that decompresses beyond the limit is an error (see
// maxEntryUncompressed), not an OOM.
func readZipEntry(ef *zip.File, name string) ([]byte, error) {
	rc, err := ef.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxEntryUncompressed+1))
	if int64(len(data)) == maxEntryUncompressed+1 {
		return nil, fmt.Errorf("asic: entry %q exceeds the %d byte uncompressed limit", name, maxEntryUncompressed)
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

const nsODFManifest = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"

// parseManifest validates the ODF v1.0 manifest the way the
// collector's manifest check does: a manifest:manifest root, exactly
// one "/" root
// entry carrying the ASiC-E media type, no signature file entries, no
// duplicate entries, a media type on every entry, and an entry for
// every container data file.
func parseManifest(doc []byte, ctr *container) []string {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}
	xd := etree.NewDocument()
	if err := xd.ReadFromBytes(doc); err != nil {
		return []string{fmt.Sprintf("manifest is not well-formed XML: %v", err)}
	}
	root := xd.Root()
	if root == nil || namespaceOf(root) != nsODFManifest || root.Tag != "manifest" {
		return []string{"manifest root element is not manifest:manifest"}
	}
	rootEntries := 0
	for _, entry := range root.ChildElements() {
		if namespaceOf(entry) != nsODFManifest || entry.Tag != "file-entry" {
			continue
		}
		fullPath := attrValue(entry, "full-path")
		mediaType := attrValue(entry, "media-type")
		if fullPath == "" || mediaType == "" {
			add("manifest entry missing full-path or media-type attribute (full-path %q)", fullPath)
			continue
		}
		switch {
		case fullPath == "/":
			rootEntries++
			if mediaType != MimeTypeContent {
				add("manifest root entry media type is %q, want %q", mediaType, MimeTypeContent)
			}
		case strings.HasPrefix(fullPath, "META-INF/"):
			add("manifest entry for signature file %q is not allowed", fullPath)
		default:
			if _, ok := ctr.manifest[fullPath]; ok {
				add("duplicate manifest entry %q", fullPath)
				continue
			}
			ctr.manifest[fullPath] = mediaType
		}
	}
	if rootEntries != 1 {
		add("manifest has %d \"/\" root entries, want 1", rootEntries)
	}
	for _, name := range ctr.fileNames() {
		if _, ok := ctr.manifest[name]; !ok {
			add("no manifest entry for data file %q", name)
		}
	}
	return errs
}

// attrValue returns the value of the first attribute with the given key
// on el, regardless of its namespace prefix.
func attrValue(el *etree.Element, key string) string {
	for _, a := range el.Attr {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// subjectLabel renders a short subject label for error messages.
func subjectLabel(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}
