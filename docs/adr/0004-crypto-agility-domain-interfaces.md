# ADR 0004 — Crypto agility: crypto behind per-domain interfaces

- Status: accepted (2026-08-28)
- Evidence: `tsa/validator_test.go`, `tsa/client_test.go` (module
  injection over the std `tsa/crypto` implementations),
  `asic/signature_test.go`, `asic/verify_test.go`,
  `asic/create_test.go`, `xades/sp_test.go`,
  `acceptance/verify_matrix_test.go`,
  `acceptance/cli_test.go` — full `go test ./...` green; the
  interoperability acceptance matrix (external harness, maintained
  outside this repo) unchanged in verdicts. The std implementations
  are exercised end to end through these suites (sign → verify
  against the Estonian e-voting collector), which pins their byte
  behavior
  (notably the ECDSA raw `r‖s` ↔ ASN.1 re-encoding pair).

## 1. Decision

Every cryptographic operation in the `asic` and `tsa` domains is
behind a small per-domain interface. Domain code holds NO
`crypto.Signer`/`crypto.PrivateKey` for its operations and performs
NO direct crypto primitives: it digests, signs, and verifies through
the injected modules.

- **No global defaults, no package-level fallback constructors.**
  The public API takes the interfaces as parameters
  (`SignBES(k, sm, dm, cert, docs, time)`, `VerifyOptions` module
  fields, `tsa.Validator`/`tsa.Client` module fields). A zero-value
  module is a hard error at the operation entry point
  ("requires the crypto modules"), not a silent standard
  implementation.
- **The standard-library implementations are provided per domain**
  (`NewStd*` constructors) and are the default the entry point
  (`cmd/asice`) constructs and injects. Swapping to an alternative
  backend (HSM, soft-token) means implementing the same interfaces
  and injecting them — domain code is untouched.
- The `xmlsig` engine (the public module `github.com/isri-pqc/xmlsig`;
  ADR 0001's engine) was already built this way and is the reference
  implementation; it is NOT modified.

## 2. The module seams

### tsa domain (`tsa/crypto`)

| Module | Surface |
|---|---|
| `DigestModule` | `GetDigestFunc(oid) (func([]byte) ([]byte, error), error)` — OID-keyed message digests (the TSA is multi-hash; SHA-2 family). |
| `SignatureVerifierModule` | `VerifySignature(cert, sigOID, signedAttrsDER, sig) error` — CMS SignerInfo signatures (RSA PKCS#1 v1.5 + ECDSA P-256/384/520). |
| `CertificateChainModule` | `VerifyChain(leaf, intermediates, roots, at) error` + `CheckKeyUsage(cert, purpose, at) error` — TSA chain building + KU/EKU gating (TSA, OCSP-signing). |

`tsa.Validator` and `tsa.Client` carry the modules as fields; `Client`
needs `DigestModule` + `SignatureVerifierModule`, `Validator` needs
all three. `NewClient`/zero `Validator` do NOT auto-populate them.

### asic domain (`asic/crypto`)

| Module | Surface |
|---|---|
| `CertificateChainModule` | `VerifyChain(leaf, intermediates, roots, at) error` + `CheckKeyUsage(cert, purpose, at) error` — BDOC chain walk (issuer-match, intermediate pool optional, no CRL/OCSP of the signer). |
| `OCSPVerifierModule` | `VerifyResponseSignature(responder, rspDER, sig, sigOID) error` + `VerifyResponderCertificate(responder, issuer, at) error`. |
| `TSTVerifierModule` | `VerifyTST(tstDER, imprintData) (time.Time, error)` — wraps a pre-constructed `tsa.Validator`; the TSA-signer pool is the verifier's trust boundary (ADR 0003). |
| `XMLSignatureSignerModule` / `XMLSignatureVerifierModule` | The `xmlsig` engine interfaces (reused, not redefined). The ASiC-E std implementations use the **collector's encoding**: ECDSA signature values as raw `r‖s` (fixed-width big-endian), NOT the engine's ASN.1 default — the byte contract the collector re-encodes from (ADR 0001 §3). |

`asic.SignBES`/`asic.SignTS` take `(k, sm, dm, cert, docs, time)`,
`asic.CreateOptions` takes `DigestModule` (+ the signer modules via
`Signer`), `asic.VerifyOptions` takes `DigestModule`,
`VerifierModule`, `ChainModule`, and — TS profile only —
`OCSPModule` + `TSTVerifier` (the old `TSTSignersPEM` field is
replaced by the pre-constructed TST verifier).

`xades.SignedProperties`/`xades.Check*` take the digest module
(`dm`) as a parameter; `xades` holds no other crypto.

## 3. What stays in the domain (the collector interop contract)

Crypto agility does NOT move the collector's acceptance policy. The
domains keep, as data checks:

- **OID allowlists** — accepted `ds:SignatureMethod` algorithms
  (RSA/ECDSA × SHA-2/3/4) in `asic.verifySignature`; accepted OCSP
  response signature OIDs (the three RSA SHA-2/3/4 variants) in
  `asic.checkOCSPResponse`; the digest-method allowlist in `xades`.
  The module gets the OID it is asked for;
  whether the OID is *accepted* is the domain's verdict.
- **Error strings pinned by tests** — "signature verification
  failed", "SHA-1 signature unsupported", "signature time-stamp
  verification failed", "unsupported OCSP response signature
  algorithm" are produced by the domain wrappers, not the modules
  (the modules return cause errors the domain wraps).
- **Key-type policy** — `NewStdSignerModule` accepts
  `*rsa.PrivateKey`/`*ecdsa.PrivateKey` only (matching
  `VerifySignature`'s accepted set); `ParseSigner` builds the std
  signer module over the parsed key, so the CLI contract is
  unchanged.

## 4. Std implementation notes

- `NewStdSignerModule(key, hash)`: RSA → PKCS#1 v1.5 DER over the
  hash; ECDSA → `ecdsa.SignASN1` then split to raw `r‖s` fixed-width
  (field bytes) — byte-identical to the pre-refactor
  `signSHA256`.
- `NewStdVerifierModule()`: ECDSA raw `r‖s` is re-encoded to ASN.1
  before `x509.Certificate.VerifySignature` (which wants DER `r,s`)
  — the inverse of the signer's encoding; this is the same
  re-encoding the collector performs.
- Digests: the ASiC-E domain reuses the engine's
  `xcrypto.NewStdXMLDigestModule()` (SHA-2/3/4, OID-keyed) — the
  domain never hashes directly.
- The TST verifier builds one `tsa.Validator` per verification
  (pool + intermediates fixed at construction); the tsa std chain
  module mirrors the pre-refactor `verifyChain`/`validAt` behavior
  (issuer match, KU/EKU, intermediate pool optional) exactly.
- OCSP: `ocsp.ParseBasicOCSPResponse` + responder signature via the
  responder certificate's `CheckSignature`; the embedded-responder
  verification is the module's
  `VerifyResponderCertificate` (chain to the signer issuer,
  ExtKeyUsageOCSPSigning, at the signature time).

## 5. Entry point and tests

`cmd/asice` (create/verify) constructs all std modules at the top of
the command and injects them: `ParseSigner` returns a `Signer`
carrying the std signer module; the tsa client gets the tsa std
modules. No module is constructed inside `asic`/`tsa`/`xades`
production code paths.

Tests: each test package wires the std modules via a small helper
(`modtest_test.go` / `testmod_test.go`) — the "default implementation"
for the test surface; negative-module tests exercise the hard
"requires the crypto modules" errors. The interoperability acceptance matrix is unchanged in verdicts: the std modules are byte- and time-behavior
identical to the pre-refactor inline crypto.
