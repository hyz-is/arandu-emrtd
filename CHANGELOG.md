# Changelog

Everything worth knowing about a release of Arandu eMRTD is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.1.0] - unreleased

Proposed as `v0.1.0`, the first public release, under the provisional path
`github.com/hyz-is/arandu-emrtd`. The public name is not confirmed yet. When it
is tagged, `unreleased` in the heading above becomes the release date; the
release workflow reads the entry by its `## [0.1.0] - ` prefix.

### Added

- `Examine(Input, *TrustStore, Options) *Report`: parses everything a device
  read from an ICAO Doc 9303 chip and runs every check it allows. A `Report`
  holds `Check`s, each an `Outcome` (`passed`, `failed`, `not_present`,
  `unverifiable`) with a `Reason` and a `Detail` free of personal data, and the
  parsed values; it holds no verdict and no boolean.
- Passive Authentication: every provided data group hashed against the SOD
  (`data_group_hash`), the SOD's CMS signature over its signed attributes
  (`sod_signature`), the Document Signer's chain to a trusted CSCA
  (`document_signer_chain`), the validity of both certificates at the
  evaluation time, the signing time inside the Document Signer's validity, and
  revocation from the CSCA's CRLs whose signature verifies
  (`document_signer_revocation`). RSA PKCS #1 v1.5, RSASSA-PSS with its own
  salt, ECDSA (X9.62 and the BSI plain format) on P-224, P-256, P-384 and P-521,
  named or as explicit parameters; SHA-1 to SHA-512, a SHA-1 pass carrying
  `weak_hash_sha1`. Brainpool and every other curve the standard library does
  not implement are `unverifiable` with `unsupported_curve`, never passed.
- Parsers, bounded and tolerant, for EF.COM (`ParseCOM`), EF.SOD (`ParseSOD`),
  DG1 and the MRZ (`ParseDG1`, `ParseMRZ`; TD1, TD2, TD3, long TD1 numbers,
  every check digit), DG2 (`ParseDG2`: the ISO/IEC 19794-5 face image as bytes,
  JPEG or JPEG 2000, the latter reported and not decoded), DG14 and
  EF.CardAccess (`ParseDG14`, `ParseCardAccess`: PACE, Chip Authentication,
  Terminal Authentication and Active Authentication infos, PACE parameter
  IDs named), DG15 and any SubjectPublicKeyInfo (`ParsePublicKeyInfo`), X.509
  certificates whatever their curve (`ParseCertificate`), and CSCA master
  lists (`ParseMasterList`, with `MasterList.CheckSigner`). Errors
  `ErrMalformed`, `ErrTooLarge`, `ErrUnsupported`; limits `MaxFileSize`,
  `MaxMasterListSize`, `MaxCRLSize`, `MaxMasterListCertificates`.
- `TrustStore`: CSCA certificates, master lists, Document Signer certificates
  and CRLs the application chose; `AddCSCA`, `AddCertificates`,
  `AddMasterList`, `AddDocumentSigner`, `AddCRL`, `CSCAs`, `Len`.
- Active Authentication: `NewChallenge` (eight bytes from `crypto/rand`) and
  `ExamineActiveAuthentication` (ISO/IEC 9796-2 scheme 1 with partial recovery
  for RSA, trailers `BC` and `xxCC`; ECDSA plain under DG14's algorithm for EC).
  In `Examine`, a signature from a DG15 key that did not pass its hash check is
  `unverifiable` with `key_not_authenticated`.
- Chip Authentication: `ChipAuthenticationClaim` and
  `ExamineChipAuthenticationClaim`, which hold what the device reports against
  the authenticated DG14 and pass with `device_asserted_only`.
- MRZ: `CheckDigit`, `CompareMRZ` field by field, and the
  `mrz_check_digits` and `mrz_printed_comparison` checks.
- `Module` (`New(Config)`, `Name`, `Routes` with none, `TrustStore`,
  `Examine`) and `Config` (`CSCACertificates`, `MasterLists`,
  `MasterListAnchors`, `PinnedMasterListSHA256`, `DocumentSigners`, `CRLs`,
  `Now`). A master list whose signature fails is refused; one whose signature
  cannot be checked here is refused unless its SHA-256 is pinned.

### Requirements

- Go 1.26, Arandu framework 0.56 or later. Pure Go: builds with
  `CGO_ENABLED=0`. No dependency beyond the standard library and the
  framework.
