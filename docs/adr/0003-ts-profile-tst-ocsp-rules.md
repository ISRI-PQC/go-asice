# ADR 0003 — TS profile (TST + OCSP) byte and time rules

- Status: accepted (Task 7, 2026-08-28)
- Evidence: `acceptance/ts_test.go` (`TestTSEndToEnd`,
  `TestTSRejectsTSTOverDifferentData`,
  `TestTSRejectsStaleTSTGenTime`), `asic/ts_test.go`
  (`TestSignTSRendersUnsignedProperties`, `TestSignTSIndex`,
  `TestSignTSGuards`) — all verified by the Estonian e-voting
  collector's `Open()` in profile TS.

Task 7 (TS sign orchestration) confirmed against the collector's
ground truth the data path of the TS profile.
One NEW byte-level rule emerged (the TST imprint target, §1); the time
windows (§2) and the USP shape/Id contract (§3) are locked. ADR 0001
rules are unchanged.

## 1. TST imprint target (new byte-level rule)

- The collector's timestamp check feeds its OFFLINE TSP client
  (`Check`) with the c14n writer output over the PARSED
  `ds:SignatureValue` element: its detached form RE-DECLARES the
  in-scope namespace bindings
  (`xmlns:asic`, `xmlns:ds`, `xmlns:xades`, sorted by prefix, ahead of
  the regular attributes) — exactly the ADR 0001 §1 locked path
  (`CanonicalizeSignedInfo` + `NSBuildParentContext`).
- The TST message imprint is therefore `SHA-256` of the canonical C14N
  1.1 `ds:SignatureValue` ELEMENT as rendered (tag, `Id` attribute,
  re-declared namespace attributes, base64 value). `tsp.Check`
  recomputes the digest over its own re-canonicalized bytes and
  compares — a mismatch rejects with `tsp.MessageImprintMismatch`
  (wrapped in `tsp.CheckTSTInfoCheckError` →
  `TimestampVerificationError` → `CheckSignatureError`).
- The TST cannot be produced before signing: the imprint covers the
  signature value. The orchestration flow is therefore
  **sign → canonicalize `ds:SignatureValue` → TST → embed
  `xades:UnsignedProperties` → re-render**. The re-render carries the
  SAME `SignedInfo` and `SignatureValue` bytes (USP is outside
  `SignedInfo`), so the signature and the imprint stay valid; this is
  what `asic.SignTS` does, taking the TST-producing callback as
  `TSData.TimeStamp` (the one TSA-shaped dependency; OCSP response and
  embedded certificates are supplied as data).
- Amended 2026-09-21: the TS flow no longer re-renders — one etree
  tree is built, signed, extended with UnsignedProperties, and
  serialized once, so the invariant holds by construction (ADR 0005).

## 2. Time windows (single-time-T pattern)

All checks run against stored values, offline. For profile TS the
collector enforces, per signature:

- OCSP check: full-response check against the signer/issuer
  certificates, at `sigTime` = the SP `SigningTime`; status must be
  Good; OCSP `producedAt` must be fresh (maxAge 1 min, maxSkew default
  300 ms).
- Timestamp check: returns the TST `genTime`; this REPLACES the
  declared SigningTime in the container report.
- `0 <= producedAt - genTime <= tsdelaytime` (60 s in the trust
  YAML), else `TimestampAndOCSPTimeMismatchError`.
- **The collector's offline TSP client `Check` does NOT inspect `genTime`
  at all** (no maxAge/future check — those run only in the live
  `Create` path). That time comparison above is the ONLY stale-TST
  defense, so an expired TST genTime is rejected as
  `TimestampAndOCSPTimeMismatchError`, not as a TSP time error.
- The locked pattern (ADR 0001 §6): one time T for the PKI,
  `SigningTime`, OCSP `producedAt`, and TST `genTime` — satisfies
  every window.

## 3. USP shape and Id contract (strict parser)

The collector's schema-driven parser enforces the exact element order
of `xades:UnsignedSignatureProperties`:

```
xades:UnsignedSignatureProperties
  xades:SignatureTimeStamp Id="S{k}-T0"          (optional; REQUIRED for TS: empty EncapsulatedTimeStamp rejects with TimestampMissingError)
    xades:EncapsulatedTimeStamp                  base64 DER TST, exactly one
  xades:CertificateValues
    xades:EncapsulatedX509Certificate Id="S{k}-RESPONDER_CERT"
    xades:EncapsulatedX509Certificate Id="S{k}-CA-CERT"
  xades:RevocationValues
    xades:OCSPValues
      xades:EncapsulatedOCSPValue Id="N{k}"      base64 DER OCSP, exactly one
```

- No CRL values, no `UnsignedDataObjectProperties`, no extra
  sub-elements — the parser rejects unknown/mis-ordered elements.
- The collector does NOT validate the embedded certificate VALUES
  (presence only); the two-certificate [responder, CA] layout follows
  the `testEIDTS.bdoc` fixture and the `xades.Ids` single-Id-per-role
  scheme — `asic.TSData.Certificates` is exactly two.
- USP is outside both canonicalized regions (ADR 0001 §1), so its
  layout affects no digest; the 60-column wrapping is fixture style
  (`xades.WrapBase64`).

## 4. API

```go
func SignTS(k int, key crypto.Signer, cert *x509.Certificate, docs []Doc, signingTime time.Time, ts TSData) ([]byte, error)

type TSData struct {
    TimeStamp    func(data []byte) ([]byte, error) // RFC 3161 TST producer (see §1)
    OCSPResponse []byte                            // DER basic OCSP response
    Certificates []*x509.Certificate               // exactly two: [OCSP responder, CA]
}
```

Guards: nil `TimeStamp`, empty `OCSPResponse`, or a certificate list
of the wrong length (or containing nil) is rejected; `TimeStamp`
errors propagate wrapped. `k < 0` and empty `docs` follow `SignBES`.
`SignBES` was refactored to share `prepareDocs`/`renderSignedDoc`
with `SignTS` (no behavior change; Task 5 tests unchanged).

## 5. Negative contract (collector error types, via `errors.CausedBy`)

| deviation                        | rejection chain                                    |
|----------------------------------|----------------------------------------------------|
| TST over other data (bad imprint)| `CheckSignatureError` → `TimestampVerificationError` |
| TST genTime > 60 s before OCSP `producedAt` | `CheckSignatureError` → `TimestampAndOCSPTimeMismatchError` |
