package emrtd

import (
	"crypto"
	"encoding/asn1"
)

// The object identifiers of ICAO Doc 9303 Parts 10 to 12, BSI TR-03110 and
// TR-03111, RFC 5652 and the algorithms they name.
var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidLDSSecurity     = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	oidCSCAMasterList  = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 2}
	oidMasterListEKU   = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 3}
	oidAAProtocol      = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 5}
	oidAttrContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASHA1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidRSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidRSASHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSASHA384    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidRSASHA512    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSASHA224    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidMGF1         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPrimeField   = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
	oidECDSASHA1    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSASHA224  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidECDSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidECDSAPlain   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1}
	oidDHPublic     = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	oidDHKeyAgree   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1}
	oidCurveP224    = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidCurveP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidCurveP521    = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidBrainpoolArc = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1}

	oidBSIProtocols = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2}
	oidPK           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1}
	oidTA           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2}
	oidCA           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3}
	oidPACE         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4}

	oidExtSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasicConstr    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// hasPrefix reports whether oid lies under the arc prefix (or is it).
func hasPrefix(oid, prefix asn1.ObjectIdentifier) bool {
	if len(oid) < len(prefix) {
		return false
	}
	return oid[:len(prefix)].Equal(prefix)
}

// hashFromOID maps a digest algorithm onto its hash, or 0.
func hashFromOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1
	case oid.Equal(oidSHA224):
		return crypto.SHA224
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	}
	return 0
}

// hashName is the name a Report gives a hash.
func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "sha1"
	case crypto.SHA224:
		return "sha224"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	}
	return ""
}

// plainHash maps the last arc of a BSI ecdsa-plain signature algorithm onto
// its hash (TR-03111): 1 SHA-1, 2 SHA-224, 3 SHA-256, 4 SHA-384, 5 SHA-512.
// RIPEMD-160 (6) is not implemented by the Go standard library and maps onto
// 0.
func plainHash(oid asn1.ObjectIdentifier) crypto.Hash {
	if len(oid) != len(oidECDSAPlain)+1 || !hasPrefix(oid, oidECDSAPlain) {
		return 0
	}
	switch oid[len(oid)-1] {
	case 1:
		return crypto.SHA1
	case 2:
		return crypto.SHA224
	case 3:
		return crypto.SHA256
	case 4:
		return crypto.SHA384
	case 5:
		return crypto.SHA512
	}
	return 0
}
