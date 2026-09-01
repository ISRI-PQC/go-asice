# ADR 0002 — Multi-file / multi-signature BES contract

- Status: accepted (Task 5, 2026-08-28)
- Evidence: `acceptance/multi_test.go`
  (`TestMultiFileBESEndToEnd`, `TestMultiSignatureBESEndToEnd`),
  `acceptance/tamper_test.go` (`TestTamperRejected`),
  `asic/signature_test.go` (`TestSignBESIndex`) — all verified by the
  Estonian e-voting collector's `Open()`.

Task 4 (ADR 0001) covered the single-signature shape. Task 5 confirmed
against the collector's ground truth the contract for containers with
several data files and/or several signature documents. No new byte-level canonicalization/ZIP rule emerged — the
ADR 0001 rules are unchanged — but the following container-level contract
is now locked for all future tasks:

## 1. Per-document parse, per-signature coverage

- Each `META-INF/signatures*.xml` entry is parsed INDEPENDENTLY
  (the collector's `Open`): the `xadesSignatures` schema restricts each document
  to exactly ONE `ds:Signature`, and the schema's `Id,attr,unique`
  qualifier scopes to that document. Identifier uniqueness therefore
  holds per document, not per container.
- The reference check then requires EVERY signature document to
  reference ALL data files of the container, plus its own
  SignedProperties reference: exactly `len(files)+1` `ds:Reference`
  elements (no extras) and exactly `len(files)`
  `xades:DataObjectFormat` elements, each DOF `MimeType` equal to the
  manifest media type. A signature that covers only a subset of the
  files is invalid.
- Consequence for emission: the `k`-th signature document must be
  rendered with the full `S{k}` identifier set (`S{k}`, `S{k}-RefId{i}`,
  `S{k}-SIG`, `S{k}-SignedProperties`, `Target="#S{k}"`) and a complete
  reference set over ALL `docs` — exactly what `asic.SignBES(k, ...)`
  does. Repeated calls with distinct `k` never collide; two documents
  both carrying `S0` would alias: the collector keys the per-signature
  OCSP/TST data maps by signature ID, so the second S0 would
  overwrite the first.

## 2. Multiple signers

- Multiple signatures may (and in real containers do) carry DIFFERENT
  signer certificates; the collector verifies each against the trust
  hierarchy independently (one certificate check per signature). The
  testutil PKI
  therefore mints a second signer leaf (`PKI.Signer2`, ECDSA P-256,
  same template and same issuer as `PKI.Signer`) for multi-signature
  fixtures.

## 3. Tamper → documented collector error types (negative contract)

From a passing multi-file BES container (5 files + S0), flipping one
byte and keeping the stored ZIP structurally valid (CRC-32 fields of the
local and central directory headers recomputed so the failure is
semantic, not transport) yields, asserted via `errors.CausedBy`:

| tampered region        | rejection chain                                        |
|------------------------|--------------------------------------------------------|
| one data file byte     | `CheckSignatureError` → `FileReferenceDigestError`    |
| one signature XML byte | `CheckSignatureError` → `SignatureVerificationError`  |

(the signature case flips the leading base64 character of the
`SignatureValue`, which changes the decoded ECDSA r‖s value;
`x509.CheckSignature` over the canonicalized `SignedInfo` then fails.)

## 4. API change

`asic.SignBES` now takes the signature index as its first parameter
(following the `xades` package convention of index-first builders):

```go
func SignBES(k int, key crypto.Signer, cert *x509.Certificate, docs []Doc, signingTime time.Time) ([]byte, error)
```

`k < 0` is rejected. `k` is the intended `META-INF/signatures{k}.xml`
position; callers store the `k`-th return value as the `k`-th
`WriteContainer` signature argument.
