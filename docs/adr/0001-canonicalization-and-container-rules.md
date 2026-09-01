# ADR 0001 — Canonicalization and container rules

- Status: accepted (Task 1 spike, 2026-08-27)
- Evidence: `asic/canon_golden_test.go`, `asic/sp_digest_golden_test.go`,
  `asic/zip_container_test.go`, `asic/signature_test.go`,
  `acceptance/spike_test.go`, `acceptance/negcheck_test.go` — all green.
  The acceptance gate: verification of a go-asice-built container by
  the Estonian e-voting collector (`TestSpikeBESEndToEnd`), plus a
  negative control proving a corrupted container is rejected. The
  collector is the interop target; verification runs through the
  external acceptance harness maintained outside this repo.

This note locks the rules the spike proved against the collector's
parser and fixtures. Future tasks (Tasks 2–5: xades builders, TS profile,
self-verifier, CLI) must not diverge from these without a new ADR.

## 1. Canonicalization

- The collector canonicalizes with inclusive C14N 1.1, algorithm URI
  `http://www.w3.org/2006/12/xml-c14n11`, and ONLY for two regions:
  (a) the SignedInfo digest input, (b) the SignedProperties digest —
  the collector re-writes the *parsed* `SignedProperties` element and
  digests those bytes.
  All other digests (files, certificate) are over raw bytes.
- Locked path: xmlsig's `canonicalizers.CanonicalizeSignedInfo(el,
  spec.CanonicalXML11AlgorithmId, ctx)` with `ctx =
  etreeutils.NSBuildParentContext(el)`. This reproduces the collector's
  canonical writer byte-for-byte:
  - **Detached-root namespace re-declaration.** The canonicalized
    element is treated as a document root, so the in-scope namespace
    declarations (collected from the element's ancestor chain via
    `NSBuildParentContext`) are re-emitted as attributes on the
    detached root, sorted by prefix. For our signature doc the
    `SignedInfo` root re-declares `xmlns:asic`, `xmlns:ds`,
    `xmlns:xades`. Omitting or reordering these breaks byte equality.
  - **Whitespace is content.** Text between child elements (the
    indentation) is preserved in the canonical form. The rendered file's
    2-space indentation therefore is *not* cosmetic: it is part of the
    canonical bytes that get digested/signed.
- Byte-equality proofs:
  - `canon_golden_test.go`: our canonical `SignedInfo` bytes == the
    `test/samples/canonicalSignedInfoEID` golden (the reference
    canonical output for the same fixture), byte-identical.
  - `sp_digest_golden_test.go`: base64(SHA-256(our canonical
    `SignedProperties` bytes)) == the SP reference digest stored in the
    fixture's `SignedInfo` — i.e. the reference digest over the
    canonical SP output for the same fixture.
- Digest value = base64(SHA-256) of the canonical bytes. SHA-256 only.

### Whitespace / base64 wrapping policy

**Superseded 2026-09-21 by ADR 0005** (layout is house style, not a
verification constraint; the canonicalizer rules of §1 above are
unchanged).

- Rendered XML uses 2-space indentation and base64 wrapped at 60 columns
  with the continuation line at column 0. CORRECTED 2026-08-27 (tasks
  2/3; the "64" line was wrong): every multi-line base64 value block in
  the BES/TS fixtures wraps at 60 columns — measured per continuation
  line in testEIDBES/TS, testMIDTS, testMultipleFiles,
  testMultipleSigners, and testEIDTM (the legacy-TM-only
  testMIDTM.bdoc is the single 64-column outlier and not a target
  profile; the "64" line apparently followed it). The wrap width is NOT
  digest-relevant for our own documents: the collector trims whitespace
  inside base64 values (TrimSpace + decode) before any check, the
  canonical regions are self-consistent at any width, and the golden
  canon/digest tests digest the FIXTURE rendering, not ours (the
  canonicalSignedInfoEID golden carries no wrap newlines: its 44-char
  digest values are single-line). 60 keeps every rendered region in the
  fixture style: SignedInfo digests, KeyInfo X509Certificate,
  SignatureValue, SigningCertificate CertDigest, and the USP
  TST/OCSP/certificate values (`xades.WrapBase64`, shared by `asic`).
- The collector reads base64 values with `TrimSpace` +
  `base64.Decode`: leading/trailing whitespace (indentation, the
  wrap-newline before `</ds:DigestValue>`) is stripped before decoding.
  So the wrapping is safe for all *value* fields (DigestValue,
  SignatureValue, X509Certificate, OCSP/TST blobs). What must NOT be
  wrapped mid-token incorrectly is nothing — any whitespace inside the
  base64 is legal for the collector, but we keep the 64/col-0 style
  for fixture-compat.
- Whitespace *between elements* is canonical content (§1); whitespace
  *inside a base64 value* is not — it is trimmed before decode.

## 2. ZIP container (ASiC-E)

- **First entry is `META-INF/mimetype`**, not the manifest. The
  collector's container check reads the first local header and
  requires:
  - marker `PK\x03\x04` @0;
  - name length @26 == len(magic) and name == `META-INF/mimetype`
    (the `magic` constant);
  - method @8 == `zip.Store` (0);
  - extra-field length @28 == 0;
  - data length @18 == len(mimetype) and content ==
    `application/vnd.etsi.asic-e+zip` (the `mimetype` constant).
  A central-directory check re-checks name + stored method + zero
  offset in the central directory.
- **Flags = 0, no data descriptors.** `archive/zip` always emits
  general-purpose flag bit 3 (0x08) and a `PK\x07\x08` data descriptor;
  the collector tolerates neither cleanly for stored entries (it
  expects sizes in the local header, no descriptor). We write flags = 0 and the
  uncompressed size in the local header. The fixture uses flag 0x0800
  (UTF-8 name bit) — that bit is harmless and the collector does not
  inspect it, but we keep flags = 0 for determinism and to avoid the
  descriptor.
- Entries are stored (method 0), uncompressed. Entry order:
  `META-INF/mimetype`, `META-INF/manifest.xml`,
  `META-INF/signatures0.xml` (…, `signatures1.xml`), then data files.
  `asic/zipwriter.go` writes the ZIP by hand (local headers → central
  directory → EOCD) because `archive/zip` cannot suppress the descriptor.
- **ODF v1.0 manifest** (`META-INF/manifest.xml`):
  `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0` namespace; one
  `manifest:file-entry` per file with namespaced `full-path` and
  `media-type` attributes; a `/` root entry. The manifest is present and
  well-formed; it is *not* itself signed or digested (the collector
  reads file names/types from the signature references, not the
  manifest digests).
- **EOCD exactness**: fixed DOS timestamp (1980-01-01 00:00:00), no
  extra fields, correct CRC-32, no comment → container bytes are
  deterministic for a given content (pinned by
  `asic/zip_container_test.go` byte-layout assertions).

## 3. Signature XML (strict shape)

The collector's parser is schema-driven and rejects deviations.
`SignBES` emits, and `asic/signature_test.go` enforces, exactly:

```
asic:XAdESSignatures (ns: asic, ds, xades)
  ds:Signature Id="S0"
    ds:SignedInfo                      (NO Id attribute)
      ds:CanonicalizationMethod Algorithm=".../xml-c14n11"
      ds:SignatureMethod Algorithm=".../ecdsa-sha256"  (or rsa-sha256)
      ds:Reference Id="S0-RefId0" URI="<file>"  …one per data file, FIRST
        (NO Type, NO Transforms)
        ds:DigestMethod / ds:DigestValue   base64(SHA-256(raw file))
      ds:Reference Id="S0-RefIdN" Type=".../01903#SignedProperties"
        URI="#S0-SignedProperties"   (the SP reference, LAST)
        ds:DigestMethod / ds:DigestValue   base64(SHA-256(canonical SP))
    ds:SignatureValue Id="S0-SIG"     (base64; ECDSA raw r||s, RSA DER)
    ds:KeyInfo → ds:X509Data → ds:X509Certificate   (base64 DER, one)
    ds:Object                          (NO attributes at all)
      xades:QualifyingProperties Target="#S0"
        xades:SignedProperties Id="S0-SignedProperties"
          xades:SignedSignatureProperties
            xades:SigningTime                       (RFC 3339)
            xades:SigningCertificate → xades:Cert
              xades:CertDigest                      base64(SHA-256(cert DER))
              xades:IssuerSerial
                ds:X509IssuerName   (RFC 4514, short names)
                ds:X509SerialNumber (decimal)
              (NO xades:SignaturePolicyIdentifier)
          xades:SignedDataObjectProperties
            xades:DataObjectFormat ObjectReference="#S0-RefId0" …one per file
              xades:MimeType       (== manifest media type; ONLY child)
        (NO xades:UnsignedProperties in BES — see §4)
```

Invariants the collector enforces (pinned in the test):
- Exactly `len(files)+1` references and `len(files)` DataObjectFormats;
  file refs first, SP ref last; no extras.
- File refs: no `Type`, no `Transforms`. SP ref: `Type`
  `http://uri.etsi.org/01903#SignedProperties`, URI `#<SP-Id>`.
- File ref `URI` is the bare file name (relative URI to the zip entry
  name). The fixtures use `#<file>`; the collector accepts both (the
  e2e is the arbiter), so we keep the bare form.
- `QualifyingProperties.Target == "#<SignatureId>"`.
- `ds:Object` carries NO attributes.
- No `SignaturePolicyIdentifier` (TS/BES profiles).
- DataObjectFormat `MimeType` must equal the manifest media type; DOF
  contains only `MimeType`.
- SigningCertificate: `CertDigest` over the exact KeyInfo cert bytes;
  `X509SerialNumber` == cert serial (decimal); `X509IssuerName` must
  round-trip the collector's RDN decode + equality check against
  `cert.Issuer.ToRDNSequence()` (with `ExtraNames = Names`).

### Why the xmlsig builder was rejected for XAdES emission

The xmlsig high-level builder (`signature_builder.go`) cannot express the
shape the collector requires:
- Its SignedProperties machinery emits `ds:SignedProperties` /
  `ds:SignatureProperty` (XML-DSig names), **not**
  `xades:QualifyingProperties` / `xades:SignedProperties`.
- It cannot set the mandatory `Type` attribute on the SignedProperties
  `ds:Reference`.
- It auto-adds an `Id` to `ds:Object` (the collector requires NO attributes).

We therefore hand-write the signature XML as a formatted string
(`fmt`), parse it into etree for region extraction + canonical context,
and reuse xmlsig's *primitives* (etree, `canonicalizers`, `spec`) — not
its XAdES object model.

## 4. BES needs no OCSP or timestamp

The collector's per-signature check gates the timestamp and OCSP
checks on the profile: they run only for profile TS. A minimal BES
signature **without** `xades:UnsignedProperties` is a valid container —
proven by `TestSpikeBESEndToEnd` (the collector's `Open()` passes, the
OCSP path did not fire, so no `UnsignedProperties`/`RevocationValues`
were added).

## 5. Cryptographic encoding

- Signature value: **ECDSA = raw r‖s** (fixed-width big-endian halves,
  2×curve-byte-size); **RSA = PKCS#1 v1.5 DER**. The collector
  re-encodes ECDSA r‖s to ASN.1 before `x509.CheckSignature`; RSA
  values are used as-is.
- Signing/digest URIs are restricted to the collector's accepted set
  (e.g. `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256`,
  `http://www.w3.org/2001/04/xmlenc#sha256`). Only those URIs are
  accepted.
- Certificate in `KeyInfo` / `SigningCertificate`: DER; `CertDigest` =
  base64(SHA-256(cert DER)) over the exact KeyInfo bytes.
- Issuer DN (`ds:X509IssuerName`): RFC 4514 with the short-name map +
  escaping, most-specific-first. Go's `ToRDNSequence` order for the
  testutil issuer is `[C, O, OU, CN]`. The encoder MUST round-trip
  the collector's RDN decode + equality check.

### GOTCHA — Go 1.27 `crypto.SignMessage` is broken (affects ALL future ECDSA signing)

`crypto.SignMessage` (and the xmlsig `crypto` signer built on it) fails
in the installed Go 1.27 toolchain with
`crypto: requested hash function unavailable: SHA-256` for ECDSA.
Workaround, used in `asic/signature.go:signSHA256`: sign the digest with
`ecdsa.SignASN1` (returns ASN.1 DER), `asn1.Unmarshal` to `r, s`, and
re-encode to fixed-width r‖s. For RSA use `rsa.SignPKCS1v15` directly.
Any future ECDSA signing code (TS timestamp re-signing, self-verifier)
must use this path, not `crypto.SignMessage`.

## 6. Time handling

- **Single reference time T drives everything.** `testutil.NewPKI(
  Options{Now: T})` sets the certificate validity window;
  `SignBES(..., signingTime T)` sets `SigningTime`. No wall-clock reads
  in the `asic` package.
- **For the TS phase (Task 3), keep all times equal to T:**
  - OCSP response `producedAt` = T (`p.OCSPResponse(producedAt=T)`);
  - TSA token `genTime` = T (`p.TimeStampToken(data, TSTOptions{GenTime: T})`);
  - `SigningTime` = T.
  Then the timestamp check (returns genTime as the container signing
  time) and the OCSP check (returns producedAt) both equal T, so
  `producedAt - SigningTime == 0`, well inside the allowed TS delay
  window.
- **TS trust YAML** (mirror `trustTS.yaml`): `tsdelaytime: 60` (seconds,
  the max allowed `producedAt - SigningTime`), `ocsp.responders` = the
  OCSP responder PEMs, `tsp.signers` = the TSA signer PEMs.
- **Collector client constraints (from the collector source, per
  0b's report):**
  - OCSP client: `maxAge = 1*time.Minute` (producedAt − thisUpdate),
    `maxSkew = 300*time.Millisecond` (producedAt vs clock).
  - TSP client: `maxAge = 1*time.Minute` (now − genTime),
    `maxSkew = 2*time.Second` (genTime vs clock).
  - TS delay window (trust YAML `tsdelaytime`, fixture = 60 s):
    `producedAt` must be in `[SigningTime, SigningTime + 60s]`.
  Setting every timestamp to the same T (and keeping the test PKI valid
  around T) satisfies all of these with zero margin used.

## 7. What Tasks 2–5 build on (API surface)

Locked, tested public surface (module `github.com/isri-pqc/asice`):

- `asic.Doc{Name, MediaType string; Data []byte}` — one data file.
- `asic.WriteContainer(w io.Writer, docs []Doc, sigs ...[]byte) error` —
  writes the full ASiC-E ZIP. `sigs` are the signature documents,
  written as `META-INF/signatures0.xml`, `signatures1.xml`, …
  (variadic, so multi-signature is already the shape).
- `asic.SignBES(key crypto.Signer, cert *x509.Certificate, docs []Doc,
  signingTime time.Time) ([]byte, error)` — renders + signs one BES
  signature document for `docs`.

Generalizations to add (do not re-derive the rules above):
- **Multi-file**: already handled — one reference + one DataObjectFormat
  per `Doc`; the SP-reference Index and `S0-RefId{i}` scheme scale.
- **Multi-signature (S0/S1 → signatures0.xml/signatures1.xml)**: the
  signature Id scheme is `S0`, `S1`, … with per-signature `S{k}-RefId{i}`,
  `S{k}-SIG`, `S{k}-SignedProperties`, `Target="#S{k}"`, and each
  document goes in its own `META-INF/signatures{k}.xml`. Parameterize the
  `S0` prefix (currently a constant in `SignBES`) by signature index so
  `signaturesN.xml` files can each carry `S{k}`.
- **Task 3 (TS)**: add `xades:UnsignedProperties` (SignatureTimeStamp +
  RevocationValues/OCSPValues) as a *sibling* of `SignedProperties`
  inside `QualifyingProperties`. USP is outside the canonicalized SP
  region and outside `SignedInfo`, so it does NOT change the SP digest
  or the SignedInfo signature — extend the render template only;
  never post-patch already-canonicalized bytes.
- **Task 4 (self-verifier)**: reuse our canonicalization path
  (`canonicalizeElement` in `asic/signature.go`) for the two digest
  regions; verify r‖s by re-encoding to ASN.1 (mirror the
  collector's re-encoding).
- **Task 5 (CLI)**: assemble `Doc` slice + `SignBES` + `WriteContainer`
  with a caller-supplied `time.Time` (never the wall clock in tests).

## 8. etree gotchas (pinned by test behavior)

- `Element.Tag` is the LOCAL name; the prefix lives in `Element.Space`.
- Find paths are relative to the receiver: `"ds:Reference"` = direct
  child only; `"//xades:SignedProperties"` = all descendants of the
  receiver. (Production code uses `"//"+tag` descendant form.)
- `Element.Text()` preserves whitespace (no trimming) — trim before
  comparing digest/value text (matches the collector's TrimSpace
  behavior for base64 fields).
