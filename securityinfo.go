package emrtd

import (
	"encoding/asn1"
	"math/big"
)

// SecurityInfos is the SET OF SecurityInfo of DG14 or EF.CardAccess (ICAO Doc
// 9303 Part 11, BSI TR-03110): what the chip says it supports for PACE, Chip
// Authentication, Terminal Authentication and Active Authentication.
type SecurityInfos struct {
	PACE                   []PACEInfo                    `json:"pace,omitempty"`
	ChipAuthentication     []ChipAuthenticationInfo      `json:"chip_authentication,omitempty"`
	ChipAuthenticationKeys []ChipAuthenticationPublicKey `json:"chip_authentication_keys,omitempty"`
	// TerminalAuthentication is the version of each TerminalAuthenticationInfo.
	TerminalAuthentication []int `json:"terminal_authentication,omitempty"`
	// ActiveAuthentication is the ActiveAuthenticationInfo, which an EC
	// Active Authentication needs for its hash, or nil.
	ActiveAuthentication *ActiveAuthenticationInfo `json:"active_authentication,omitempty"`
	// Other is the OID of every SecurityInfo not interpreted, such as domain
	// parameter infos.
	Other []string `json:"other,omitempty"`
}

// PACEInfo is one PACE protocol the chip offers.
type PACEInfo struct {
	Protocol string `json:"protocol"`
	// KeyAgreement is "dh" or "ecdh"; Mapping is "generic", "integrated" or
	// "chip_authentication"; Cipher is "3des", "aes128", "aes192" or "aes256".
	// Each is empty for an OID outside the table.
	KeyAgreement string `json:"key_agreement,omitempty"`
	Mapping      string `json:"mapping,omitempty"`
	Cipher       string `json:"cipher,omitempty"`
	Version      int    `json:"version"`
	// ParameterID is the standardized domain parameter, or -1.
	ParameterID int `json:"parameter_id"`
	// Parameters names it: "P-256", "brainpoolP256r1", "modp2048_256".
	Parameters string `json:"parameters,omitempty"`
}

// ChipAuthenticationInfo is one Chip Authentication protocol the chip offers.
type ChipAuthenticationInfo struct {
	Protocol     string `json:"protocol"`
	KeyAgreement string `json:"key_agreement,omitempty"`
	Cipher       string `json:"cipher,omitempty"`
	Version      int    `json:"version"`
	// KeyID is the key it uses, or -1 when the chip has one key.
	KeyID int64 `json:"key_id"`
}

// ChipAuthenticationPublicKey is one Chip Authentication key of DG14.
type ChipAuthenticationPublicKey struct {
	Protocol     string         `json:"protocol"`
	KeyAgreement string         `json:"key_agreement,omitempty"`
	KeyID        int64          `json:"key_id"`
	Key          *PublicKeyInfo `json:"key"`
}

// ActiveAuthenticationInfo is DG14's ActiveAuthenticationInfo.
type ActiveAuthenticationInfo struct {
	Version int `json:"version"`
	// SignatureAlgorithm is the OID of the algorithm, an ecdsa-plain one for
	// EC keys, or empty.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	oid asn1.ObjectIdentifier
}

type securityInfoASN1 struct {
	Protocol asn1.ObjectIdentifier
	Required asn1.RawValue
	Optional asn1.RawValue `asn1:"optional"`
}

// paceParameters names the standardized domain parameters of ICAO Doc 9303
// Part 11 by parameter ID.
var paceParameters = map[int]string{
	0: "modp1024_160", 1: "modp2048_224", 2: "modp2048_256",
	8: "P-192", 9: "brainpoolP192r1", 10: "P-224", 11: "brainpoolP224r1",
	12: "P-256", 13: "brainpoolP256r1", 14: "brainpoolP320r1", 15: "P-384",
	16: "brainpoolP384r1", 17: "brainpoolP512r1", 18: "P-521",
}

var ciphers = map[int]string{1: "3des", 2: "aes128", 3: "aes192", 4: "aes256"}

// ParseDG14 parses DG14.
func ParseDG14(b []byte) (*SecurityInfos, error) {
	file, err := readFile(b, tagDG14)
	if err != nil {
		return nil, err
	}
	return parseSecurityInfos(file.value)
}

// ParseCardAccess parses EF.CardAccess, which is a SET OF SecurityInfo with
// no file tag of its own.
func ParseCardAccess(b []byte) (*SecurityInfos, error) {
	if len(b) > MaxFileSize {
		return nil, tooLarge("file of %d bytes", len(b))
	}
	return parseSecurityInfos(b)
}

func parseSecurityInfos(der []byte) (*SecurityInfos, error) {
	var set asn1.RawValue
	rest, err := asn1.Unmarshal(der, &set)
	if err != nil {
		return nil, malformed("SecurityInfos: %v", err)
	}
	if !padding(rest) || set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet {
		return nil, malformed("SecurityInfos is not one SET")
	}
	out := &SecurityInfos{}
	items := set.Bytes
	count := 0
	for len(items) > 0 {
		if count++; count > maxSecurityInfos {
			return nil, tooLarge("more than %d SecurityInfos", maxSecurityInfos)
		}
		var si securityInfoASN1
		rest, err := asn1.Unmarshal(items, &si)
		if err != nil {
			return nil, malformed("SecurityInfo: %v", err)
		}
		items = rest
		if err := out.add(si); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *SecurityInfos) add(si securityInfoASN1) error {
	p := si.Protocol
	switch {
	case p.Equal(oidAAProtocol):
		version, err := smallInt(si.Required)
		if err != nil {
			return err
		}
		info := &ActiveAuthenticationInfo{Version: version}
		if len(si.Optional.FullBytes) > 0 {
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(si.Optional.FullBytes, &oid); err != nil {
				return malformed("ActiveAuthenticationInfo signature algorithm")
			}
			info.oid = oid
			info.SignatureAlgorithm = oid.String()
		}
		s.ActiveAuthentication = info

	case hasPrefix(p, oidPACE) && len(p) == len(oidPACE)+2:
		version, err := smallInt(si.Required)
		if err != nil {
			return err
		}
		info := PACEInfo{Protocol: p.String(), Version: version, ParameterID: -1, Cipher: ciphers[p[len(p)-1]]}
		info.KeyAgreement, info.Mapping = paceMapping(p[len(p)-2])
		if len(si.Optional.FullBytes) > 0 {
			id, err := smallInt(si.Optional)
			if err != nil {
				return err
			}
			info.ParameterID = id
			info.Parameters = paceParameters[id]
		}
		s.PACE = append(s.PACE, info)

	case hasPrefix(p, oidCA) && len(p) == len(oidCA)+2:
		version, err := smallInt(si.Required)
		if err != nil {
			return err
		}
		info := ChipAuthenticationInfo{Protocol: p.String(), Version: version, KeyID: -1, Cipher: ciphers[p[len(p)-1]]}
		info.KeyAgreement = keyAgreement(p[len(p)-2])
		if len(si.Optional.FullBytes) > 0 {
			if info.KeyID, err = keyID(si.Optional); err != nil {
				return err
			}
		}
		s.ChipAuthentication = append(s.ChipAuthentication, info)

	case hasPrefix(p, oidPK) && len(p) == len(oidPK)+1:
		if si.Required.Tag != asn1.TagSequence {
			return malformed("ChipAuthenticationPublicKeyInfo without a SubjectPublicKeyInfo")
		}
		key, err := ParsePublicKeyInfo(si.Required.FullBytes)
		if err != nil {
			return err
		}
		info := ChipAuthenticationPublicKey{Protocol: p.String(), KeyAgreement: keyAgreement(p[len(p)-1]), KeyID: -1, Key: key}
		if len(si.Optional.FullBytes) > 0 {
			if info.KeyID, err = keyID(si.Optional); err != nil {
				return err
			}
		}
		s.ChipAuthenticationKeys = append(s.ChipAuthenticationKeys, info)

	case p.Equal(oidTA):
		version, err := smallInt(si.Required)
		if err != nil {
			return err
		}
		s.TerminalAuthentication = append(s.TerminalAuthentication, version)

	default:
		s.Other = append(s.Other, p.String())
	}
	return nil
}

func keyAgreement(arc int) string {
	switch arc {
	case 1:
		return "dh"
	case 2:
		return "ecdh"
	}
	return ""
}

// paceMapping reads the arc of id-PACE that names the key agreement and the
// mapping: 1 DH-GM, 2 ECDH-GM, 3 DH-IM, 4 ECDH-IM, 6 ECDH-CAM.
func paceMapping(arc int) (string, string) {
	switch arc {
	case 1:
		return "dh", "generic"
	case 2:
		return "ecdh", "generic"
	case 3:
		return "dh", "integrated"
	case 4:
		return "ecdh", "integrated"
	case 6:
		return "ecdh", "chip_authentication"
	}
	return "", ""
}

func smallInt(raw asn1.RawValue) (int, error) {
	var v int
	if rest, err := asn1.Unmarshal(raw.FullBytes, &v); err != nil || len(rest) > 0 {
		return 0, malformed("INTEGER expected")
	}
	if v < 0 || v > 1<<16 {
		return 0, malformed("INTEGER %d out of range", v)
	}
	return v, nil
}

func keyID(raw asn1.RawValue) (int64, error) {
	var v *big.Int
	if rest, err := asn1.Unmarshal(raw.FullBytes, &v); err != nil || len(rest) > 0 || v == nil {
		return 0, malformed("keyId")
	}
	if !v.IsInt64() || v.Sign() < 0 {
		return 0, malformed("keyId out of range")
	}
	return v.Int64(), nil
}
