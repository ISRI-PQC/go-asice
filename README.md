# asice

ASiC-E container tool for the **XML XAdES form** (TS 102 918 / BDOC 2.1.2
shape): create and self-verify containers in the **BES** and **TS**
profiles.

## Security Notice

This codebase was scanned on 2026-09-01 with
[deepsec](https://github.com/vercel-labs/deepsec) (an AI-assisted
security scanner) against a project threat model covering hostile
`.asice` containers, operator-supplied key/PEM inputs, and an
attacker-influenced TSA endpoint. Every exported finding was triaged
and resolved: the confirmed defects were fixed with regression tests,
and the one remaining finding was verified as a false positive and
pinned by a regression test so the behavior is preserved.

That scan is a point-in-time audit, not a security certification. This
library creates and verifies cryptographic containers: before relying
on it in production, review the code, validate its behavior against
your threat model, and test with your own certificates, TSA endpoints,
and containers.

## Verification

- **Self-verification** — the repo's own checks: container structure,
  file digests, the signature, the certificate chain at signing time,
  and — for the TS profile — the embedded TST and OCSP values. The
  `verify` command runs these.
- **Interop** — the design target is the **Estonian e-voting
  collector**: containers produced here must verify under it.
  Interoperability is enforced by an external acceptance harness
  (maintained outside this repo) that verifies CLI-produced containers
  against the collector. In-repo, behavior is pinned by the hermetic
  test PKI and the golden-file fixtures in `test/samples/`.

## Layout

| Path            | Contents                                                               | Purpose                                           |
| --------------- | -------------------------------------------------------------------- | ------------------------------------------------- |
| `xades/`        | XAdES property builders (SignedProperties, UnsignedProperties)         | builds the XAdES SP/USP in the signature document |
| `asic/`         | container writer, BES/TS signing, `Create` orchestration, self-verify  | the core ASiC-E create and verify path            |
| `tsa/`          | RFC 3161 codecs + HTTP client + validator (+ exported test TSA server) | parse and verify TSTs (issue them in tests)       |
| `testutil/`     | exported hermetic test PKI incl. OCSP/TST generation (test support)    | deterministic, test PKI                 |
| `test/samples/` | hermetic fixtures, generated — see that README                         | self-consistency pins for the golden tests        |
| `cmd/asice`     | the CLI (below)                                                        | the user-facing entry point                       |
| `docs/adr/`     | design decisions                                                       | records why design decisions were made            |
| `asic/spec`     | ASiC spec pointers (TS 102 918, TS 103 174)                            | normative reference for the ASiC profile          |
| `xades/spec`    | XAdES spec pointers (TS 101 903, TS 103 171)                           | normative reference for XAdES                     |
| `bdoc/spec`     | BDOC spec pointer (2.1.2:2014)                                         | normative reference for the container format      |

The XML-DSig engine is the public module `github.com/isri-pqc/xmlsig`
(dependency in `go.mod`); this repo has no `xmlsig/` submodule.

## Build & test

Requires Go 1.25+.

```
go build ./...
go vet ./...
go test ./... -count=1
```

## CLI

```
asice create -o out.asice --cert signer.pem [--chain chain.pem]
    [--profile bes|ts] [--ocsp-file ocsp.der] [--tst <tsa-url>]
    [--tst-signers tsa.pem] [--signing-time <RFC3339>] doc1 [doc2 ...]

asice verify in.asice --roots roots.pem [--intermediates int.pem]
    [--tst-signers tsa.pem] [--ocsp-responders ocsp-responder.pem]
    [--profile bes|ts]
```

Exit codes: `0` ok, `1` create/verify failure, `2` usage error.
`asice --help` prints this usage. The CLI is built on cobra + fang and
also provides `--version`, a `completion` command (shell completions),
and a hidden `man` command (manpage generation).

### create

- `-o` — output container path (required).
- `--cert` — signer file: PEM with one `CERTIFICATE` block (the signer
  certificate) and one private key block (`PRIVATE KEY` / `RSA PRIVATE
KEY` / `EC PRIVATE KEY`) (required).
- `--profile` — `bes` (default) or `ts`.
- `--chain` — **ts profile**: PEM with exactly two certificates, the
  OCSP responder first and the CA second (embedded in
  `xades:CertificateValues`); ignored for bes.
- `--ocsp-file` — **ts profile**: DER basic OCSP response for the
  signer certificate.
- `--tst` — **ts profile**: RFC 3161 TSA endpoint URL (HTTP).
- `--tst-signers` — **ts profile**: PEM with the TSA signing
  certificate(s) (the TSA client identifies and validates the token
  signer against these).
- `--signing-time` — RFC 3339 signing time; default: now (UTC). For the
  ts profile use one consistent time: signing time = OCSP producedAt =
  TST genTime.
- `doc1 [doc2 ...]` — one or more document paths (flat names; media
  types guessed from the extension, else `application/octet-stream`).

### verify

- container path — the single positional argument; flags may be placed
  before or after it.
- `--roots` — PEM trust anchor(s) (required).
- `--intermediates` — PEM intermediate CA(s).
- `--tst-signers` — **required for ts**: PEM TSA signing certificate(s).
- `--ocsp-responders` — ts, optional: PEM configured OCSP responder(s);
  when absent the embedded responder is matched against the signer's
  issuer instead.
- `--profile` — `bes` (default) or `ts`.

Prints a human-readable report (data files, per-signature status with
signer and signing time, and actionable errors).

## Examples

BES (minimal):

```
asice create -o out.asice --cert signer.pem --profile bes contract.pdf
asice verify out.asice --roots root.pem --intermediates issuer.pem --profile bes
```

TS (against a live TSA; one consistent time — here the OCSP response's
producedAt — for `--signing-time`):

```
asice create -o out.asice --cert signer.pem --profile ts \
    --chain ocsp-responder-then-ca.pem --ocsp-file ocsp.der \
    --tst https://tsa.example/tsp --tst-signers tsa.pem \
    --signing-time 2026-08-28T10:00:00Z contract.pdf
asice verify out.asice --roots root.pem --intermediates issuer.pem \
    --profile ts --tst-signers tsa.pem --ocsp-responders ocsp-responder.pem
```

## Crypto agility

Every cryptographic operation sits behind a small per-domain module
interface (ADR 0004); the domain code performs no direct crypto
primitives and holds no keys of its own.

- `asic/crypto` — the certificate chain walk (issuer-match at signing
  time, ContentCommitment key usage on the leaf), embedded-OCSP response
  verification, TST verification, plus the XML-DSig signer/verifier
  modules of the `xmlsig` engine.
- `tsa/crypto` — OID-keyed message digests, CMS SignerInfo signature
  verification, and TSA chain building with key/extended-key usage
  gating.

The standard-library implementations (`NewStd*` constructors) cover RSA
PKCS#1 v1.5 and ECDSA P-256/384/521. The XML-DSig signature value is
encoded per W3C XML Signature 1.1 section 6.4.3 — ECDSA as raw `r‖s`
(fixed-width big-endian halves, RFC 4050 section 3.3 / IEEE 1363 E3.1),
RSA as PKCS#1 v1.5 DER. The public API takes the modules as parameters
with no global defaults: a zero-value module is a hard error at the
operation entry point. An alternative backend (HSM, soft token, or a
post-quantum scheme — the `xmlsig` engine registers the ML-DSA-44/65/87
algorithm URIs, with implementations supplied as custom modules) is
plugged in by implementing the same interfaces and injecting them; the
container and signature layout is algorithm-agnostic (the algorithm ID
lives in `ds:SignatureMethod`).

## Byte-level rules

The container, canonicalization, and TS-profile rules are locked down by
the ADRs in `docs/adr/` (0001: canonicalization and container layout —
inclusive C14N 1.1, ZIP magic/manifest/entry layout, base64 wrapping;
0002: multi-file / multi-signature BES contract; 0003: TS-profile TST
and OCSP embedding, single-time-T pattern; 0004: crypto agility —
crypto behind per-domain interfaces; 0005: signature XML layout is
house style) and pinned by the golden tests against `test/samples/`,
which holds the hermetic fixtures. Interoperability with the Estonian
e-voting collector is the design target and is enforced by the external
acceptance harness maintained outside this repo.

## Dependencies

| Module                                                        | License         | Role                                                       |
| ------------------------------------------------------------- | --------------- | ---------------------------------------------------------- |
| [github.com/isri-pqc/xmlsig](https://github.com/isri-pqc/xmlsig) | Apache-2.0 | the XML-DSig engine: C14N 1.1 canonicalization, digest/signature primitives, signature builder |
| [github.com/beevik/etree](https://github.com/beevik/etree)     | BSD-2-Clause    | XML document tree handling                                 |
| [github.com/spf13/cobra](https://github.com/spf13/cobra)       | Apache-2.0      | CLI command framework                                      |
| [github.com/charmbracelet/fang](https://github.com/charmbracelet/fang) | MIT       | CLI UX (completions, manpage generation)                   |

This project is licensed under the MIT License (see [LICENSE](LICENSE)).
