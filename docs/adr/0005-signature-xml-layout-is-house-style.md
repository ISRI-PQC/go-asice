# ADR 0005 — Signature XML layout is house style

- Status: accepted (2026-09-21)
- Evidence: `acceptance/ts_test.go` (`TestTSEndToEnd`,
  `TestTSRejectsTSTOverDifferentData`,
  `TestTSRejectsStaleTSTGenTime`), `acceptance/multi_test.go`,
  `acceptance/tamper_test.go`, `asic/ts_test.go`
  (`TestSignTSRendersUnsignedProperties`), kept by the parallel
  refactor; acceptance bar (the Estonian e-voting collector's
  `Open()`, via the external acceptance harness) unchanged.

## 1. Background

- The byte-parity came from spike-era risk mitigation: the spike's
  risk note ("Copy their fixtures' formatting exactly ...
  byte-for-byte in tests") and ADR 0001's "Whitespace / base64
  wrapping policy" section.
- ADR 0001 was right about the mechanism: inclusive C14N 1.1 is
  whitespace-PRESERVING, not whitespace-normalizing — it sorts
  attributes and re-declares namespaces at the detached root, but
  copies text nodes (indentation, base64 line breaks) verbatim; the
  layout IS part of the canonical bytes digested/signed.

## 2. Decision

Fixture byte-parity is dropped; the rendered layout is house style:
2-space indentation (`etree Document.Indent(2)`), single-line base64
(60-column wrapping dropped — the collector decodes base64 with
`TrimSpace`, so width is irrelevant). Any layout verifies because the
digests are self-referential: the renderer canonicalizes its own
output and signs it; the collector re-parses and re-canonicalizes the
produced document.
Byte-parity was a TEST-EVIDENCE choice, not a verification requirement.

## 3. What remains hard

- **TST-flow self-consistency.** The TST message imprint covers the
  canonical `ds:SignatureValue` element (ADR 0003 §1). The refactor
  makes this hold by construction: one etree tree is built, signed,
  extended with `xades:UnsignedProperties`, and serialized once (no
  two-pass re-render), so the `SignedInfo`/`SignatureValue` canonical
  bytes are invariant.
- **The collector's structural parser strictness.** Element shape/order, `Id`
  scheme, `Type` attribute, reference order (ADR 0001 §3, 0003 §3) —
  whitespace-independent, stays hard.

## 4. Scope of test change

- Fixture byte-diffs become semantic shape comparisons
  (element-for-element: tag order, attributes, whitespace-trimmed
  text) — same fixtures, weaker (layout-independent) comparison.
- Canonicalizer golden tests UNCHANGED
  (`asic/canon_golden_test.go`, `asic/sp_digest_golden_test.go`): they
  prove our canonicalizer matches the collector's c14n writer on the
  reference fixture input; they constrain nothing about our output
  layout.
- Acceptance bar unchanged: the collector's `Open()` (suites above).

## 5. Supersedes

- ADR 0001, "Whitespace / base64 wrapping policy": superseded — layout
  is house style; ADR 0001 §1's canonicalizer rules are unchanged.
- ADR 0003 §1, the re-render sentence ("The re-render carries the
  SAME `SignedInfo` and `SignatureValue` bytes ..."): replaced by the
  single-tree construction (§3).
