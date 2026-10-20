package emrtd

// Outcome is what one check established. It is evidence about one property of
// the chip data, never a judgement of the document or of the person: the
// application reads the outcomes and decides.
type Outcome string

// The four outcomes a check has.
const (
	// OutcomePassed is a property this package checked and found to hold.
	OutcomePassed Outcome = "passed"
	// OutcomeFailed is a property this package checked and found not to
	// hold: a hash that differs, a signature that does not verify, a revoked
	// certificate, a check digit that is wrong.
	OutcomeFailed Outcome = "failed"
	// OutcomeNotPresent is a check with nothing to read: the file, the
	// response or the list it needs was not provided.
	OutcomeNotPresent Outcome = "not_present"
	// OutcomeUnverifiable is a check this package cannot run on what it was
	// given: a Brainpool key, an algorithm it does not implement, a CSCA
	// missing from the trust store, a key that Passive Authentication did not
	// cover. It is never a pass.
	OutcomeUnverifiable Outcome = "unverifiable"
)

// CheckName names a check in a Report.
type CheckName string

// The checks a Report holds.
const (
	// CheckFileStructure is whether a file parses as its structure.
	CheckFileStructure CheckName = "file_structure"
	// CheckDataGroupHash is whether a provided data group hashes to the
	// value the SOD carries for it.
	CheckDataGroupHash CheckName = "data_group_hash"
	// CheckSODSignature is whether the SOD's CMS signature verifies with the
	// Document Signer key, over signed attributes that carry the digest of
	// the LDS security object.
	CheckSODSignature CheckName = "sod_signature"
	// CheckDocumentSignerChain is whether the Document Signer certificate was
	// issued by a CSCA certificate of the trust store.
	CheckDocumentSignerChain CheckName = "document_signer_chain"
	// CheckDocumentSignerValidity is whether the evaluation time falls inside
	// the Document Signer certificate's validity.
	CheckDocumentSignerValidity CheckName = "document_signer_validity"
	// CheckCSCAValidity is whether the evaluation time falls inside the
	// issuing CSCA certificate's validity.
	CheckCSCAValidity CheckName = "csca_validity"
	// CheckSigningTime is whether the SOD's signing time falls inside the
	// Document Signer certificate's validity.
	CheckSigningTime CheckName = "signing_time"
	// CheckDocumentSignerRevocation is whether a CRL of the issuing CSCA,
	// whose signature verifies, lists the Document Signer certificate.
	CheckDocumentSignerRevocation CheckName = "document_signer_revocation"
	// CheckCOMConsistency is whether EF.COM, which is not signed, lists the
	// same data groups as the SOD.
	CheckCOMConsistency CheckName = "com_consistency"
	// CheckMRZCheckDigits is whether every check digit of the DG1 MRZ is
	// right.
	CheckMRZCheckDigits CheckName = "mrz_check_digits"
	// CheckMRZPrintedComparison is whether the DG1 MRZ equals, field by
	// field, the MRZ read from the printed page.
	CheckMRZPrintedComparison CheckName = "mrz_printed_comparison"
	// CheckActiveAuthentication is whether the chip's signature over the
	// server's challenge verifies with the DG15 key.
	CheckActiveAuthentication CheckName = "active_authentication"
	// CheckChipAuthenticationClaim is whether what the device reports about
	// Chip Authentication is consistent with the authenticated DG14.
	CheckChipAuthenticationClaim CheckName = "chip_authentication_claim"
	// CheckMasterListSignature is whether a master list's CMS signature
	// verifies with the signer certificate it carries.
	CheckMasterListSignature CheckName = "master_list_signature"
	// CheckMasterListSigner is whether a CSCA issued the master list signer
	// certificate.
	CheckMasterListSigner CheckName = "master_list_signer"
)

// Reason is the machine-readable cause of an outcome. A passed check may carry
// one too, when it passed with a caveat such as a SHA-1 hash.
type Reason string

// The reasons a check carries.
const (
	ReasonMalformed              Reason = "malformed"
	ReasonUnsupportedStructure   Reason = "unsupported_structure"
	ReasonTagMismatch            Reason = "tag_mismatch"
	ReasonNotProvided            Reason = "not_provided"
	ReasonNotInSOD               Reason = "not_in_sod"
	ReasonHashMismatch           Reason = "hash_mismatch"
	ReasonUnsupportedHash        Reason = "unsupported_hash"
	ReasonWeakHash               Reason = "weak_hash_sha1"
	ReasonSignatureInvalid       Reason = "signature_invalid"
	ReasonMessageDigestMismatch  Reason = "message_digest_mismatch"
	ReasonContentTypeMismatch    Reason = "content_type_mismatch"
	ReasonNoSignedAttributes     Reason = "no_signed_attributes"
	ReasonUnsupportedAlgorithm   Reason = "unsupported_algorithm"
	ReasonUnsupportedCurve       Reason = "unsupported_curve"
	ReasonUnsupportedKey         Reason = "unsupported_key"
	ReasonKeyAlgorithmMismatch   Reason = "key_algorithm_mismatch"
	ReasonDocumentSignerMissing  Reason = "document_signer_missing"
	ReasonNoTrustStore           Reason = "no_trust_store"
	ReasonCSCANotFound           Reason = "csca_not_found"
	ReasonIssuerNotCA            Reason = "issuer_not_ca"
	ReasonKeyUsage               Reason = "key_usage"
	ReasonExpired                Reason = "expired"
	ReasonNotYetValid            Reason = "not_yet_valid"
	ReasonNoSigningTime          Reason = "no_signing_time"
	ReasonNoCRL                  Reason = "no_crl"
	ReasonCRLSignature           Reason = "crl_signature_unverified"
	ReasonCRLStale               Reason = "crl_stale"
	ReasonRevoked                Reason = "revoked"
	ReasonCOMDiffers             Reason = "com_differs"
	ReasonCheckDigit             Reason = "check_digit"
	ReasonFieldDiffers           Reason = "field_differs"
	ReasonFormatDiffers          Reason = "format_differs"
	ReasonJPEG2000NotDecoded     Reason = "jpeg2000_not_decoded"
	ReasonImageTypeDiffers       Reason = "image_type_differs"
	ReasonNoImage                Reason = "no_image"
	ReasonChallengeLength        Reason = "challenge_length"
	ReasonISO9796Header          Reason = "iso9796_header"
	ReasonISO9796Trailer         Reason = "iso9796_trailer"
	ReasonAAAlgorithmUnknown     Reason = "aa_algorithm_unknown"
	ReasonKeyNotAuthenticated    Reason = "key_not_authenticated"
	ReasonRSAKeyTooSmall         Reason = "rsa_key_too_small"
	ReasonDeviceReportedFailure  Reason = "device_reported_failure"
	ReasonProtocolNotInDG14      Reason = "protocol_not_in_dg14"
	ReasonKeyNotInDG14           Reason = "key_not_in_dg14"
	ReasonDeviceAssertedOnly     Reason = "device_asserted_only"
	ReasonUnknownDeviceStatus    Reason = "unknown_device_status"
	ReasonMasterListSignerChain  Reason = "master_list_signer_chain"
	ReasonMasterListSignerNoAnch Reason = "master_list_signer_no_anchor"
)

// Check is one check's outcome, with the file it concerns and why.
type Check struct {
	// Name is what was checked.
	Name CheckName `json:"name"`
	// File is the elementary file the check concerns ("DG1", "EF.SOD",
	// "EF.COM", "EF.CardAccess"), or empty.
	File string `json:"file,omitempty"`
	// Outcome is what the check established.
	Outcome Outcome `json:"outcome"`
	// Reason is the machine-readable cause, empty for a plain pass.
	Reason Reason `json:"reason,omitempty"`
	// Detail is a sentence for a person reading the evidence. It carries no
	// personal data: no name, no document number, no date of birth.
	Detail string `json:"detail,omitempty"`
}

func passed(name CheckName, file string, reason Reason, detail string) Check {
	return Check{Name: name, File: file, Outcome: OutcomePassed, Reason: reason, Detail: detail}
}

func failed(name CheckName, file string, reason Reason, detail string) Check {
	return Check{Name: name, File: file, Outcome: OutcomeFailed, Reason: reason, Detail: detail}
}

func notPresent(name CheckName, file string, reason Reason, detail string) Check {
	return Check{Name: name, File: file, Outcome: OutcomeNotPresent, Reason: reason, Detail: detail}
}

func unverifiable(name CheckName, file string, reason Reason, detail string) Check {
	return Check{Name: name, File: file, Outcome: OutcomeUnverifiable, Reason: reason, Detail: detail}
}
