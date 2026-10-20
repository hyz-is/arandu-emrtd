---
name: emrtd-module
description: Change the Arandu eMRTD package itself. Use when the request is to "add a check", "parse DG11", "support another signature algorithm", "support Brainpool", "the SOD does not parse", "a passport fails the chain", "change the Report", "add a reason", "fix a parser", "the fuzzer found a crash", "Active Authentication fails for an RSA chip", "read a master list", or any edit to the .go files at the root of this repository. Covers where each responsibility lives, the outcome rules, the parsing limits, how fixtures are built, and what must be tested.
license: MIT
---

# Changing the package

## Where things live

`report.go` runs every check, in order, inside `Examine`; a new check is a
`CheckName` in `outcome.go`, a function that returns a `Check`, and one line in
`Examine`. Parsing is per file (`lds.go`, `mrz.go`, `dg2.go`,
`securityinfo.go`, `sod.go`, `masterlist.go`); cryptography is in
`publickey.go`, `signature.go`, `certificate.go`, `cms.go`, `truststore.go`,
`active.go`. Object identifiers are only in `oids.go`.

## The outcome rules

- `passed`: checked and holds. A caveat goes in `Reason` (`weak_hash_sha1`,
  `crl_stale`, `device_asserted_only`, `no_signed_attributes`).
- `failed`: checked and does not hold.
- `not_present`: nothing to read.
- `unverifiable`: cannot be checked here. A key with `Key == nil`, an
  unimplemented algorithm, a CSCA absent, a key that Passive Authentication did
  not cover. **Never** turn one of these into `passed`.

No boolean, score or verdict goes into a type reachable from `Report` or
`MasterList`; `tests/Unit/decision_test.go` walks them. A `Detail` names no
person: no name, document number or date from the MRZ.

## Brainpool and other curves

`crypto/ecdsa` computes on P-224, P-256, P-384 and P-521 only.
`ParsePublicKeyInfo` names every other curve (Brainpool by OID, explicit
parameters by matching the NIST ones) and leaves `Key` nil with
`Unsupported`. Supporting Brainpool means a curve implementation with a
verified permissive licence or one written here and tested against published
vectors -- a decision for the owner, not a quiet addition. `gmrtd` is out: its
`osanderson/brainpool` dependency has no licence file.

## Parsing

Every reader goes through `readTLV`/`children` (LDS files) or
`encoding/asn1` (CMS, certificates), and every count and size is bounded by the
constants of `tlv.go`. Trust no length. A parse error is `ErrMalformed`,
`ErrTooLarge` or `ErrUnsupported`, wrapped with what was wrong; `Examine` turns
it into a `file_structure` check and never fails.

## Tests

Fixtures are built in `tests/Feature/fixture_test.go`: a test CSCA of Utopia,
Document Signers, SODs signed over generated data groups, ISO/IEC 9796-2
signatures, master lists, CRLs, hand-built certificates for keys crypto/x509
will not encode. Add the case there; never commit bytes read from a document.
A new parser gets a fuzz target in `tests/Feature/fuzz_test.go` with a seed
from the builder, and is run with `-fuzz` for at least 30 seconds before the
commit.
