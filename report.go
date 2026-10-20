package emrtd

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Input is what the device read from the chip and the server holds about
// the session, as it reaches the server.
//
// Every file is the bytes of the elementary file exactly as read, tag and
// length included: the SOD hashes the whole data group, so a file rebuilt or
// re-encoded on the device does not hash to its value.
type Input struct {
	// COM is EF.COM, or nil.
	COM []byte
	// SOD is EF.SOD. Without it nothing is authenticated.
	SOD []byte
	// DataGroups is each data group read, by number (1 for DG1).
	DataGroups map[int][]byte
	// CardAccess is EF.CardAccess, or nil.
	CardAccess []byte
	// PrintedMRZ is the MRZ read from the printed page, as text, or empty.
	PrintedMRZ string
	// ActiveAuthentication is the challenge the server issued and the chip's
	// response, or nil.
	ActiveAuthentication *ActiveAuthenticationResponse
	// ChipAuthentication is what the device reports about Chip
	// Authentication, or nil.
	ChipAuthentication *ChipAuthenticationClaim
}

// Options are the parameters of one examination.
type Options struct {
	// Time is the evaluation time certificate validity and CRL freshness are
	// read at. Zero is time.Now().
	Time time.Time
}

// Report is the evidence one examination produced: every check with its
// outcome, and what was parsed.
//
// It holds no verdict. There is no field that says the document is genuine,
// and no outcome stands for the others: the application reads the checks it
// requires and decides, and a check that is not OutcomePassed is not a pass,
// whatever its reason.
//
// The parsed values are only as authentic as their checks: the MRZ is DG1's
// whether or not DG1 passed its hash check.
type Report struct {
	EvaluatedAt time.Time `json:"evaluated_at"`
	Checks      []Check   `json:"checks"`

	COM *COM `json:"com,omitempty"`
	SOD *SOD `json:"sod,omitempty"`
	// DocumentSigner is the certificate that signed the SOD, when it was
	// found; CSCA is the trusted certificate that issued it, when the chain
	// passed.
	DocumentSigner *Certificate `json:"document_signer,omitempty"`
	CSCA           *Certificate `json:"csca,omitempty"`
	// MRZ is DG1's; PrintedMRZ is the printed page's, when given;
	// MRZComparison compares them.
	MRZ           *MRZ              `json:"mrz,omitempty"`
	PrintedMRZ    *MRZ              `json:"printed_mrz,omitempty"`
	MRZComparison []FieldComparison `json:"mrz_comparison,omitempty"`
	// Faces is DG2's face images.
	Faces []FaceImage `json:"faces,omitempty"`
	// DG14 and CardAccess are the security infos of those files.
	DG14       *SecurityInfos `json:"dg14,omitempty"`
	CardAccess *SecurityInfos `json:"card_access,omitempty"`
	// ActiveAuthenticationKey is DG15's key.
	ActiveAuthenticationKey *PublicKeyInfo `json:"active_authentication_key,omitempty"`
}

// Find returns the first check of the name for the file ("" for any file).
func (r *Report) Find(name CheckName, file string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name && (file == "" || c.File == file) {
			return c, true
		}
	}
	return Check{}, false
}

// Outcome is the outcome of the first check of the name for the file, or
// OutcomeNotPresent when the report has none.
func (r *Report) Outcome(name CheckName, file string) Outcome {
	if c, ok := r.Find(name, file); ok {
		return c.Outcome
	}
	return OutcomeNotPresent
}

func (r *Report) add(c ...Check) { r.Checks = append(r.Checks, c...) }

// Examine parses everything in the input and runs every check it allows:
// Passive Authentication against the trust store, the MRZ check digits and
// the comparison with the printed MRZ, Active Authentication, and the Chip
// Authentication claim. It never fails: a file that does not parse is a
// failed file_structure check, and the checks that needed it say so.
//
// trust may be nil, and then the chain is unverifiable.
func Examine(in Input, trust *TrustStore, opts Options) *Report {
	at := opts.Time
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	r := &Report{EvaluatedAt: at}

	numbers := make([]int, 0, len(in.DataGroups))
	for n := range in.DataGroups {
		numbers = append(numbers, n)
	}
	slices.Sort(numbers)

	// What parses.
	if in.COM != nil {
		com, err := ParseCOM(in.COM)
		r.add(structure(FileCOM, err, "", ""))
		r.COM = com
	}
	var sod *SOD
	if in.SOD != nil {
		var err error
		sod, err = ParseSOD(in.SOD)
		r.add(structure(FileSOD, err, "", ""))
		r.SOD = sod
	} else {
		r.add(notPresent(CheckFileStructure, FileSOD, ReasonNotProvided, "no EF.SOD: no data group can be authenticated"))
	}
	for _, n := range numbers {
		r.add(r.parseDataGroup(n, in.DataGroups[n]))
	}
	if in.CardAccess != nil {
		ca, err := ParseCardAccess(in.CardAccess)
		r.add(structure(FileCardAccess, err, "", ""))
		r.CardAccess = ca
	}

	// Passive Authentication.
	r.add(dataGroupHashes(sod, in.DataGroups, numbers)...)
	r.passive(sod, trust, at)
	r.add(comConsistency(r.COM, sod))

	// The MRZ.
	if r.MRZ != nil {
		r.add(mrzDigits(r.MRZ))
	}
	if strings.TrimSpace(in.PrintedMRZ) != "" {
		r.add(r.comparePrinted(in.PrintedMRZ))
	}

	// Active and Chip Authentication.
	if in.ActiveAuthentication != nil {
		r.add(r.activeAuthentication(in.ActiveAuthentication))
	} else if r.ActiveAuthenticationKey != nil {
		r.add(notPresent(CheckActiveAuthentication, FileName(15), ReasonNotProvided, "the chip has an Active Authentication key and no response was given"))
	}
	if in.ChipAuthentication != nil || r.DG14 != nil && len(r.DG14.ChipAuthenticationKeys) > 0 {
		r.add(ExamineChipAuthenticationClaim(in.ChipAuthentication, r.DG14, r.Outcome(CheckDataGroupHash, FileName(14))))
	}
	return r
}

// structure is the file_structure check of a parse error.
func structure(file string, err error, reason Reason, detail string) Check {
	switch {
	case err == nil:
		return passed(CheckFileStructure, file, reason, detail)
	case errors.Is(err, ErrUnsupported):
		return unverifiable(CheckFileStructure, file, ReasonUnsupportedStructure, err.Error())
	}
	return failed(CheckFileStructure, file, ReasonMalformed, err.Error())
}

func (r *Report) parseDataGroup(n int, b []byte) Check {
	file := FileName(n)
	tag := DataGroupTag(n)
	if tag == 0 {
		return failed(CheckFileStructure, file, ReasonMalformed, "there is no data group of this number")
	}
	if len(b) > 0 && len(b) <= MaxFileSize {
		if t, _, err := readTLV(b); err == nil && t.tag != tag {
			return failed(CheckFileStructure, file, ReasonTagMismatch, fmt.Sprintf("the file opens with tag %X, which is DG%d's", t.tag, DataGroupNumber(t.tag)))
		}
	}
	switch n {
	case 1:
		m, err := ParseDG1(b)
		r.MRZ = m
		return structure(file, err, "", "")
	case 2:
		faces, err := ParseDG2(b)
		r.Faces = faces
		if err != nil {
			return structure(file, err, "", "")
		}
		for _, f := range faces {
			if f.DeclaredType >= 0 && (f.DeclaredType == 0) != (f.Format == ImageJPEG) {
				return passed(CheckFileStructure, file, ReasonImageTypeDiffers, "the facial record declares one image type and the image bytes are another")
			}
		}
		for _, f := range faces {
			switch f.Format {
			case ImageJPEG2000:
				return passed(CheckFileStructure, file, ReasonJPEG2000NotDecoded, "a face image is JPEG 2000, which is returned as bytes and not decoded here")
			case ImageUnknown:
				return passed(CheckFileStructure, file, ReasonNoImage, "a face image is in neither JPEG nor JPEG 2000")
			}
		}
		return passed(CheckFileStructure, file, "", "")
	case 14:
		infos, err := ParseDG14(b)
		r.DG14 = infos
		return structure(file, err, "", "")
	case 15:
		file15, err := readFile(b, tagDG15)
		if err != nil {
			return structure(file, err, "", "")
		}
		key, err := ParsePublicKeyInfo(file15.value)
		r.ActiveAuthenticationKey = key
		return structure(file, err, "", "")
	}
	_, err := readFile(b, tag)
	if err != nil {
		return structure(file, err, "", "")
	}
	return passed(CheckFileStructure, file, "", "the file is a well-formed data object; its content is not interpreted here")
}

// dataGroupHashes checks every data group the SOD hashes or the input holds.
func dataGroupHashes(sod *SOD, groups map[int][]byte, provided []int) []Check {
	const name = CheckDataGroupHash
	if sod == nil {
		var out []Check
		for _, n := range provided {
			out = append(out, unverifiable(name, FileName(n), ReasonNotProvided, "no SOD to hold the data group against"))
		}
		return out
	}
	all := slices.Clone(provided)
	for _, n := range sod.DataGroups() {
		if !slices.Contains(all, n) {
			all = append(all, n)
		}
	}
	slices.Sort(all)
	var out []Check
	for _, n := range all {
		file := FileName(n)
		want := sod.hashOf(n)
		b, given := groups[n]
		switch {
		case want == nil:
			out = append(out, failed(name, file, ReasonNotInSOD, "the data group was provided and the SOD does not hash it"))
		case !given:
			out = append(out, notPresent(name, file, ReasonNotProvided, "the SOD hashes this data group and it was not provided"))
		case sod.hash == 0:
			out = append(out, unverifiable(name, file, ReasonUnsupportedHash, "the SOD's hash algorithm is not implemented here"))
		default:
			h := sod.hash.New()
			h.Write(fileSpan(b))
			if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
				out = append(out, failed(name, file, ReasonHashMismatch, "the data group does not hash to the SOD's value"))
				continue
			}
			reason := Reason("")
			if sod.hash == crypto.SHA1 {
				reason = ReasonWeakHash
			}
			out = append(out, passed(name, file, reason, ""))
		}
	}
	return out
}

// passive runs the signature, chain, validity and revocation checks of
// Passive Authentication.
func (r *Report) passive(sod *SOD, trust *TrustStore, at time.Time) {
	names := []CheckName{CheckSODSignature, CheckDocumentSignerChain, CheckDocumentSignerValidity, CheckCSCAValidity, CheckSigningTime, CheckDocumentSignerRevocation}
	if sod == nil {
		for _, n := range names {
			r.add(notPresent(n, FileSOD, ReasonNotProvided, "no SOD that parses"))
		}
		return
	}
	ds := sod.cms.findSigner(trust.documentSigners())
	if ds == nil {
		r.add(unverifiable(CheckSODSignature, FileSOD, ReasonDocumentSignerMissing, "neither the SOD nor the trust store holds the certificate its signer info names"))
		for _, n := range names[1:] {
			r.add(unverifiable(n, FileSOD, ReasonDocumentSignerMissing, "no Document Signer certificate"))
		}
		return
	}
	r.DocumentSigner = ds
	sig := sod.cms.checkSigner(ds)
	r.add(Check{Name: CheckSODSignature, File: FileSOD, Outcome: sig.outcome, Reason: sig.reason, Detail: sig.detail})

	// The chain.
	var csca *Certificate
	switch {
	case trust == nil || trust.Len() == 0:
		r.add(unverifiable(CheckDocumentSignerChain, FileSOD, ReasonNoTrustStore, "the trust store holds no CSCA certificate"))
	case ds.keyUsage >= 0 && ds.keyUsage&keyUsageDigitalSignature == 0:
		r.add(failed(CheckDocumentSignerChain, FileSOD, ReasonKeyUsage, "the Document Signer certificate does not allow digital signatures"))
	default:
		res, issuer := chainTo(ds, trust.CSCAs(), at)
		detail := res.detail
		if res.reason == ReasonCSCANotFound {
			detail = "no trusted CSCA is named as the issuer " + ds.Issuer
		}
		r.add(Check{Name: CheckDocumentSignerChain, File: FileSOD, Outcome: res.outcome, Reason: res.reason, Detail: detail})
		csca = issuer
		r.CSCA = issuer
	}

	// Validity.
	if reason := ds.validAt(at); reason != "" {
		r.add(failed(CheckDocumentSignerValidity, FileSOD, reason, "the evaluation time is outside the Document Signer certificate's validity"))
	} else {
		r.add(passed(CheckDocumentSignerValidity, FileSOD, "", ""))
	}
	switch {
	case csca == nil:
		r.add(unverifiable(CheckCSCAValidity, FileSOD, ReasonCSCANotFound, "the chain to a CSCA did not pass"))
	case csca.validAt(at) != "":
		r.add(failed(CheckCSCAValidity, FileSOD, csca.validAt(at), "the evaluation time is outside the CSCA certificate's validity"))
	default:
		r.add(passed(CheckCSCAValidity, FileSOD, "", ""))
	}
	switch {
	case sod.SigningTime.IsZero():
		r.add(notPresent(CheckSigningTime, FileSOD, ReasonNoSigningTime, "the SOD's signed attributes carry no signing time"))
	case ds.validAt(sod.SigningTime) != "":
		r.add(failed(CheckSigningTime, FileSOD, ds.validAt(sod.SigningTime), "the SOD's signing time is outside the Document Signer certificate's validity"))
	default:
		r.add(passed(CheckSigningTime, FileSOD, "", ""))
	}

	// Revocation.
	if csca == nil {
		r.add(unverifiable(CheckDocumentSignerRevocation, FileSOD, ReasonCSCANotFound, "no CSCA whose CRLs apply"))
	} else {
		r.add(trust.revocation(ds, csca, at))
	}
}

// comConsistency compares EF.COM's tag list with the SOD's data groups.
func comConsistency(com *COM, sod *SOD) Check {
	const name = CheckCOMConsistency
	if com == nil || sod == nil {
		return notPresent(name, FileCOM, ReasonNotProvided, "EF.COM and the SOD are both needed")
	}
	// Either may name a data group the other omits; that difference is what
	// is reported, and the SOD is the one that is signed.
	if !slices.Equal(com.DataGroups, sod.DataGroups()) {
		return failed(name, FileCOM, ReasonCOMDiffers, fmt.Sprintf("EF.COM lists %v and the SOD hashes %v", com.DataGroups, sod.DataGroups()))
	}
	return passed(name, FileCOM, "", "")
}

func mrzDigits(m *MRZ) Check {
	var wrong []string
	for _, d := range m.CheckDigits {
		if d.Outcome != OutcomePassed {
			wrong = append(wrong, d.Field)
		}
	}
	if len(wrong) > 0 {
		return failed(CheckMRZCheckDigits, FileName(1), ReasonCheckDigit, "wrong check digit for "+strings.Join(wrong, ", "))
	}
	return passed(CheckMRZCheckDigits, FileName(1), "", "")
}

func (r *Report) comparePrinted(text string) Check {
	const name = CheckMRZPrintedComparison
	printed, err := ParseMRZ(text)
	if err != nil {
		return failed(name, FileName(1), ReasonMalformed, "the printed MRZ does not parse: "+err.Error())
	}
	r.PrintedMRZ = printed
	if r.MRZ == nil {
		return notPresent(name, FileName(1), ReasonNotProvided, "no DG1 MRZ to compare with")
	}
	r.MRZComparison = CompareMRZ(r.MRZ, printed)
	var differ []string
	for _, f := range r.MRZComparison {
		if f.Outcome != OutcomePassed {
			differ = append(differ, f.Field)
		}
	}
	if len(differ) > 0 {
		return failed(name, FileName(1), ReasonFieldDiffers, "the printed MRZ differs in "+strings.Join(differ, ", "))
	}
	return passed(name, FileName(1), "", "")
}

func (r *Report) activeAuthentication(resp *ActiveAuthenticationResponse) Check {
	if r.ActiveAuthenticationKey == nil {
		return notPresent(CheckActiveAuthentication, FileName(15), ReasonNotProvided, "a response was given and there is no DG15 key that parses")
	}
	var info *ActiveAuthenticationInfo
	if r.DG14 != nil {
		info = r.DG14.ActiveAuthentication
	}
	c := ExamineActiveAuthentication(r.ActiveAuthenticationKey, info, resp.Challenge, resp.Signature)
	if c.Outcome != OutcomePassed {
		return c
	}
	// An EC key needs DG14's algorithm, so DG14 has to be authentic too.
	if r.Outcome(CheckDataGroupHash, FileName(15)) != OutcomePassed ||
		r.ActiveAuthenticationKey.Algorithm == KeyEC && r.Outcome(CheckDataGroupHash, FileName(14)) != OutcomePassed {
		return unverifiable(CheckActiveAuthentication, FileName(15), ReasonKeyNotAuthenticated,
			"the signature verifies with the DG15 key, and the key did not pass Passive Authentication, so it proves nothing about the chip")
	}
	return c
}
