package emrtd

import (
	"encoding/asn1"
	"slices"
	"time"
)

// MasterList is a CSCA master list (ICAO Doc 9303 Part 12, 9): a CMS
// SignedData whose content is a set of CSCA certificates, signed by a master
// list signer whose certificate a CSCA issued.
//
// A master list is only as trusted as the decision to load it. ParseMasterList
// checks its signature with the signer certificate it carries and records the
// outcome; CheckSigner places the signer under a CSCA. Neither makes the
// certificates in it anyone's CSCAs: loading them into a TrustStore is the
// application's decision.
type MasterList struct {
	Version int `json:"version"`
	// Certificates is every certificate of the list that parsed.
	Certificates []*Certificate `json:"certificates"`
	// Skipped is how many entries of the list did not parse as certificates.
	Skipped int `json:"skipped"`
	// Signer is the master list signer certificate, or nil when the CMS does
	// not carry the one its signer info names.
	Signer *Certificate `json:"signer"`
	// SigningTime is the signingTime signed attribute, or zero.
	SigningTime time.Time `json:"signing_time,omitzero"`
	// Signature is the outcome of checking the CMS signature with Signer.
	Signature Check `json:"signature"`
	// SHA256 is the hex SHA-256 of the master list as given.
	SHA256 string `json:"sha256"`
}

type cscaMasterList struct {
	Version  int
	CertList asn1.RawValue
}

// ParseMasterList parses a CSCA master list, as the ICAO PKD and the issuing
// states publish it: the DER of the CMS ContentInfo (the .ml file).
func ParseMasterList(der []byte) (*MasterList, error) {
	if len(der) > MaxMasterListSize {
		return nil, tooLarge("master list of %d bytes", len(der))
	}
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	if !sd.eContentType.Equal(oidCSCAMasterList) {
		return nil, malformed("the CMS signs %s, not a CSCA master list", sd.eContentType)
	}
	var ml cscaMasterList
	if rest, err := asn1.Unmarshal(sd.eContent, &ml); err != nil || len(rest) > 0 {
		return nil, malformed("CscaMasterList: %v", err)
	}
	if ml.CertList.Class != asn1.ClassUniversal || ml.CertList.Tag != asn1.TagSet {
		return nil, malformed("certList is not a SET")
	}
	out := &MasterList{Version: ml.Version, SigningTime: sd.signingTime, SHA256: sha256Hex(der)}
	list := ml.CertList.Bytes
	for len(list) > 0 {
		if len(out.Certificates)+out.Skipped >= MaxMasterListCertificates {
			return nil, tooLarge("more than %d certificates", MaxMasterListCertificates)
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(list, &raw)
		if err != nil {
			return nil, malformed("certList entry: %v", err)
		}
		list = rest
		c, err := ParseCertificate(raw.FullBytes)
		if err != nil {
			out.Skipped++
			continue
		}
		out.Certificates = append(out.Certificates, c)
	}

	out.Signer = sd.findSigner(nil)
	const name = CheckMasterListSignature
	if out.Signer == nil {
		out.Signature = unverifiable(name, "", ReasonDocumentSignerMissing, "the master list does not carry its signer's certificate")
		return out, nil
	}
	res := sd.checkSigner(out.Signer)
	out.Signature = Check{Name: name, Outcome: res.outcome, Reason: res.reason, Detail: res.detail}
	return out, nil
}

// CheckSigner checks that a CSCA issued the master list signer's certificate
// and that both were valid at the time given. The CSCA is looked for among
// anchors, the CSCA certificates the application already trusts for the
// issuer of the list; with no anchors, among the list's own certificates,
// which proves only that the list is consistent with itself.
func (m *MasterList) CheckSigner(anchors []*Certificate, at time.Time) Check {
	const name = CheckMasterListSigner
	if m.Signer == nil {
		return unverifiable(name, "", ReasonDocumentSignerMissing, "the master list does not carry its signer's certificate")
	}
	pool := anchors
	reason := Reason("")
	if len(anchors) == 0 {
		pool = m.Certificates
		reason = ReasonMasterListSignerNoAnch
	}
	if m.Signer.keyUsage >= 0 && m.Signer.keyUsage&keyUsageDigitalSignature == 0 {
		return failed(name, "", ReasonKeyUsage, "the master list signer certificate does not allow digital signatures")
	}
	if len(m.Signer.extKeyUse) > 0 && !slices.ContainsFunc(m.Signer.extKeyUse, func(o asn1.ObjectIdentifier) bool { return o.Equal(oidMasterListEKU) }) {
		return failed(name, "", ReasonKeyUsage, "the master list signer certificate is not for master list signing")
	}
	res, _ := chainTo(m.Signer, pool, at)
	if res.outcome == OutcomePassed && !at.IsZero() {
		if r := m.Signer.validAt(at); r != "" {
			return failed(name, "", r, "the master list signer certificate is not valid at the evaluation time")
		}
	}
	if res.outcome == OutcomePassed && res.reason == "" {
		res.reason = reason
		if reason != "" {
			res.detail = "the signer was issued by a certificate inside the list itself, which no anchor confirms"
		}
	}
	return Check{Name: name, Outcome: res.outcome, Reason: res.reason, Detail: res.detail}
}
