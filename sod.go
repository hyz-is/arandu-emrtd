package emrtd

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"time"
)

// SOD is EF.SOD, the Document Security Object: the hash of every data group,
// signed by the Document Signer.
type SOD struct {
	// Version is the LDSSecurityObject version: 0 for LDS 1.7, 1 for 1.8.
	Version int `json:"version"`
	// HashAlgorithm is the data group hash: "sha1", "sha224", "sha256",
	// "sha384", "sha512", or the OID of one this package does not implement.
	HashAlgorithm string `json:"hash_algorithm"`
	// DataGroupHashes is every hash the SOD carries, by ascending number.
	DataGroupHashes []DataGroupHash `json:"data_group_hashes"`
	// LDSVersion and UnicodeVersion are the LDSVersionInfo of a version 1
	// object, or empty.
	LDSVersion     string `json:"lds_version,omitempty"`
	UnicodeVersion string `json:"unicode_version,omitempty"`
	// SigningTime is the signingTime signed attribute, which the signer
	// asserts and nothing proves, or zero.
	SigningTime time.Time `json:"signing_time,omitzero"`
	// Certificates is every certificate the SOD carries; ICAO Doc 9303 has
	// the Document Signer certificate among them.
	Certificates []*Certificate `json:"certificates"`
	// Raw is the file as given.
	Raw []byte `json:"-"`

	hash crypto.Hash
	cms  *signedData
}

// DataGroupHash is one data group's hash in the SOD.
type DataGroupHash struct {
	DataGroup int `json:"data_group"`
	// Hash is hexadecimal.
	Hash string `json:"hash"`

	raw []byte
}

type ldsSecurityObject struct {
	Version             int
	HashAlgorithm       pkix.AlgorithmIdentifier
	DataGroupHashValues []dataGroupHashASN1
	LDSVersionInfo      ldsVersionInfo `asn1:"optional"`
}

type dataGroupHashASN1 struct {
	Number int
	Value  []byte
}

type ldsVersionInfo struct {
	LDSVersion     string `asn1:"printable"`
	UnicodeVersion string `asn1:"printable"`
}

// ParseSOD parses EF.SOD: the 0x77 file, the CMS SignedData inside it, and
// the LDSSecurityObject it signs. It checks no signature; Examine does.
func ParseSOD(b []byte) (*SOD, error) {
	file, err := readFile(b, tagSOD)
	if err != nil {
		return nil, err
	}
	sd, err := parseSignedData(file.value)
	if err != nil {
		return nil, err
	}
	if !sd.eContentType.Equal(oidLDSSecurity) {
		return nil, malformed("the SOD signs %s, not an LDSSecurityObject", sd.eContentType)
	}
	var lso ldsSecurityObject
	if rest, err := asn1.Unmarshal(sd.eContent, &lso); err != nil || len(rest) > 0 {
		return nil, malformed("LDSSecurityObject: %v", err)
	}
	if lso.Version < 0 || lso.Version > 1 {
		return nil, malformed("LDSSecurityObject version %d", lso.Version)
	}
	sod := &SOD{
		Version:        lso.Version,
		LDSVersion:     lso.LDSVersionInfo.LDSVersion,
		UnicodeVersion: lso.LDSVersionInfo.UnicodeVersion,
		SigningTime:    sd.signingTime,
		Certificates:   sd.certificates,
		Raw:            bytes.Clone(b),
		hash:           hashFromOID(lso.HashAlgorithm.Algorithm),
		cms:            sd,
	}
	sod.HashAlgorithm = hashName(sod.hash)
	if sod.hash == 0 {
		sod.HashAlgorithm = lso.HashAlgorithm.Algorithm.String()
	}
	if len(lso.DataGroupHashValues) == 0 || len(lso.DataGroupHashValues) > 16 {
		return nil, malformed("%d data group hashes", len(lso.DataGroupHashValues))
	}
	for _, h := range lso.DataGroupHashValues {
		if h.Number < 1 || h.Number > 16 {
			return nil, malformed("hash of data group %d", h.Number)
		}
		if sod.hash != 0 && len(h.Value) != sod.hash.Size() {
			return nil, malformed("DG%d hash of %d bytes for %s", h.Number, len(h.Value), sod.HashAlgorithm)
		}
		if len(h.Value) == 0 || len(h.Value) > 64 {
			return nil, malformed("DG%d hash of %d bytes", h.Number, len(h.Value))
		}
		if slices.ContainsFunc(sod.DataGroupHashes, func(d DataGroupHash) bool { return d.DataGroup == h.Number }) {
			return nil, malformed("DG%d hashed twice", h.Number)
		}
		sod.DataGroupHashes = append(sod.DataGroupHashes, DataGroupHash{
			DataGroup: h.Number,
			Hash:      hex.EncodeToString(h.Value),
			raw:       h.Value,
		})
	}
	slices.SortFunc(sod.DataGroupHashes, func(a, b DataGroupHash) int { return a.DataGroup - b.DataGroup })
	return sod, nil
}

// DataGroups is the numbers of the data groups the SOD hashes, ascending.
func (s *SOD) DataGroups() []int {
	out := make([]int, 0, len(s.DataGroupHashes))
	for _, h := range s.DataGroupHashes {
		out = append(out, h.DataGroup)
	}
	return out
}

func (s *SOD) hashOf(n int) []byte {
	for _, h := range s.DataGroupHashes {
		if h.DataGroup == n {
			return h.raw
		}
	}
	return nil
}
