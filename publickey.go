package emrtd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
)

// KeyAlgorithm is the family of a public key.
type KeyAlgorithm string

// The families a PublicKeyInfo names.
const (
	KeyRSA     KeyAlgorithm = "rsa"
	KeyEC      KeyAlgorithm = "ec"
	KeyDH      KeyAlgorithm = "dh"
	KeyUnknown KeyAlgorithm = "unknown"
)

// The largest keys this package computes with. A larger one is reported as
// unsupported rather than spending unbounded time on a hostile input.
const (
	maxRSABits   = 8192
	maxFieldBits = 1024
)

// PublicKeyInfo is a SubjectPublicKeyInfo as an eMRTD carries it: in a
// certificate, in DG14 for Chip Authentication, in DG15 for Active
// Authentication.
//
// Key is set only when this package can compute with the key: RSA, and EC on
// P-224, P-256, P-384 or P-521, named or written as explicit parameters equal
// to them. Every other key -- Brainpool above all, which many CSCAs and chips
// use and the Go standard library does not implement -- is parsed and named,
// Key is nil, and Unsupported says why: a check that needs it is
// unverifiable, never passed.
type PublicKeyInfo struct {
	Algorithm KeyAlgorithm `json:"algorithm"`
	// Curve names an EC key's curve: "P-256", "brainpoolP256r1", "explicit"
	// for explicit parameters of an unknown curve, or an OID.
	Curve string `json:"curve,omitempty"`
	// Bits is the modulus size of an RSA key, or the field size of an EC key.
	Bits int `json:"bits,omitempty"`
	// SHA256 is the hex SHA-256 of the SubjectPublicKeyInfo DER.
	SHA256 string `json:"sha256"`
	// Unsupported is why Key is nil, or empty.
	Unsupported Reason `json:"unsupported,omitempty"`
	// Key is a *rsa.PublicKey or an *ecdsa.PublicKey, or nil.
	Key crypto.PublicKey `json:"-"`
	// Raw is the SubjectPublicKeyInfo DER.
	Raw []byte `json:"-"`
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkcs1PublicKey struct {
	N *big.Int
	E *big.Int
}

type ecParameters struct {
	Version int
	FieldID struct {
		FieldType  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	Curve struct {
		A    []byte
		B    []byte
		Seed asn1.BitString `asn1:"optional"`
	}
	Base     []byte
	Order    *big.Int
	Cofactor *big.Int `asn1:"optional"`
}

// ParsePublicKeyInfo parses a SubjectPublicKeyInfo DER.
//
// It returns an error only for a structure that does not decode. A key of an
// algorithm or curve this package does not compute with is a PublicKeyInfo
// with Key nil and Unsupported set.
func ParsePublicKeyInfo(der []byte) (*PublicKeyInfo, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, malformed("SubjectPublicKeyInfo: %v", err)
	}
	if len(rest) > 0 {
		return nil, malformed("bytes after the SubjectPublicKeyInfo")
	}
	raw := der[:len(der)-len(rest)]
	sum := sha256.Sum256(raw)
	info := &PublicKeyInfo{
		Algorithm: KeyUnknown,
		SHA256:    hex.EncodeToString(sum[:]),
		Raw:       bytes.Clone(raw),
	}
	alg := spki.Algorithm.Algorithm
	key := spki.PublicKey.RightAlign()
	switch {
	case alg.Equal(oidRSA), alg.Equal(oidRSAPSS):
		info.Algorithm = KeyRSA
		return info, parseRSA(info, key)
	case alg.Equal(oidECPublicKey), hasPrefix(alg, oidPK) && len(alg) == len(oidPK)+1 && alg[len(alg)-1] == 2:
		info.Algorithm = KeyEC
		return info, parseEC(info, spki.Algorithm.Parameters, key)
	case alg.Equal(oidDHPublic), alg.Equal(oidDHKeyAgree), hasPrefix(alg, oidPK) && len(alg) == len(oidPK)+1 && alg[len(alg)-1] == 1:
		info.Algorithm = KeyDH
		info.Unsupported = ReasonUnsupportedKey
		return info, nil
	}
	info.Unsupported = ReasonUnsupportedKey
	return info, nil
}

func parseRSA(info *PublicKeyInfo, key []byte) error {
	var k pkcs1PublicKey
	rest, err := asn1.Unmarshal(key, &k)
	if err != nil || len(rest) > 0 || k.N == nil || k.E == nil || k.N.Sign() <= 0 || k.E.Sign() <= 0 {
		return malformed("RSA public key")
	}
	info.Bits = k.N.BitLen()
	switch {
	case info.Bits > maxRSABits:
		info.Unsupported = ReasonUnsupportedKey
	case !k.E.IsInt64() || k.E.Int64() < 3 || k.E.Int64() > 1<<31-1 || k.E.Bit(0) == 0:
		info.Unsupported = ReasonUnsupportedKey
	case k.N.Bit(0) == 0:
		return malformed("even RSA modulus")
	default:
		info.Key = &rsa.PublicKey{N: k.N, E: int(k.E.Int64())}
	}
	return nil
}

// nistCurves are the curves the Go standard library computes with.
var nistCurves = []struct {
	oid   asn1.ObjectIdentifier
	curve elliptic.Curve
}{
	{oidCurveP224, elliptic.P224()},
	{oidCurveP256, elliptic.P256()},
	{oidCurveP384, elliptic.P384()},
	{oidCurveP521, elliptic.P521()},
}

// brainpoolNames are the Brainpool curves of RFC 5639 by the last arc of
// their OID under 1.3.36.3.3.2.8.1.1.
var brainpoolNames = map[int]string{
	1: "brainpoolP160r1", 2: "brainpoolP160t1", 3: "brainpoolP192r1", 4: "brainpoolP192t1",
	5: "brainpoolP224r1", 6: "brainpoolP224t1", 7: "brainpoolP256r1", 8: "brainpoolP256t1",
	9: "brainpoolP320r1", 10: "brainpoolP320t1", 11: "brainpoolP384r1", 12: "brainpoolP384t1",
	13: "brainpoolP512r1", 14: "brainpoolP512t1",
}

// brainpoolBits is the field size of each Brainpool curve by the same arc.
var brainpoolBits = map[int]int{
	1: 160, 2: 160, 3: 192, 4: 192, 5: 224, 6: 224, 7: 256, 8: 256,
	9: 320, 10: 320, 11: 384, 12: 384, 13: 512, 14: 512,
}

func parseEC(info *PublicKeyInfo, params asn1.RawValue, point []byte) error {
	var curve elliptic.Curve
	switch {
	case params.Tag == asn1.TagOID && params.Class == asn1.ClassUniversal:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(params.FullBytes, &oid); err != nil {
			return malformed("EC curve OID")
		}
		for _, c := range nistCurves {
			if oid.Equal(c.oid) {
				curve = c.curve
			}
		}
		if curve == nil {
			info.Unsupported = ReasonUnsupportedCurve
			info.Curve = oid.String()
			if hasPrefix(oid, oidBrainpoolArc) && len(oid) == len(oidBrainpoolArc)+1 {
				if name, ok := brainpoolNames[oid[len(oid)-1]]; ok {
					info.Curve = name
					info.Bits = brainpoolBits[oid[len(oid)-1]]
				}
			}
			return nil
		}
	case params.Tag == asn1.TagSequence && params.Class == asn1.ClassUniversal:
		c, bits, err := explicitCurve(params.FullBytes)
		if err != nil {
			return err
		}
		if c == nil {
			info.Unsupported = ReasonUnsupportedCurve
			info.Curve = "explicit"
			info.Bits = bits
			return nil
		}
		curve = c
	default:
		// implicitlyCA, or no parameters: the curve is not in the key.
		info.Unsupported = ReasonUnsupportedCurve
		info.Curve = "implicit"
		return nil
	}
	info.Curve = curve.Params().Name
	info.Bits = curve.Params().BitSize
	if len(point) == 0 || point[0] != 0x04 {
		// A compressed point is valid X9.62, and rare enough in eMRTDs that
		// it is reported rather than decompressed.
		info.Unsupported = ReasonUnsupportedKey
		return nil
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return malformed("EC point: %v", err)
	}
	info.Key = pub
	return nil
}

// explicitCurve matches explicit EC domain parameters with the curves the
// standard library computes with. It returns nil and the field size for
// parameters of any other curve.
func explicitCurve(der []byte) (elliptic.Curve, int, error) {
	var p ecParameters
	if rest, err := asn1.Unmarshal(der, &p); err != nil || len(rest) > 0 {
		return nil, 0, malformed("explicit EC parameters")
	}
	if !p.FieldID.FieldType.Equal(oidPrimeField) {
		return nil, 0, nil
	}
	var prime *big.Int
	if _, err := asn1.Unmarshal(p.FieldID.Parameters.FullBytes, &prime); err != nil || prime == nil || prime.Sign() <= 0 {
		return nil, 0, malformed("explicit EC prime")
	}
	bits := prime.BitLen()
	if bits > maxFieldBits {
		return nil, 0, tooLarge("EC field of %d bits", bits)
	}
	a := new(big.Int).SetBytes(p.Curve.A)
	b := new(big.Int).SetBytes(p.Curve.B)
	for _, c := range nistCurves {
		cp := c.curve.Params()
		minus3 := new(big.Int).Sub(cp.P, big.NewInt(3))
		size := (cp.BitSize + 7) / 8
		base := make([]byte, 1+2*size)
		base[0] = 0x04
		cp.Gx.FillBytes(base[1 : 1+size])
		cp.Gy.FillBytes(base[1+size:])
		if prime.Cmp(cp.P) == 0 && a.Cmp(minus3) == 0 && b.Cmp(cp.B) == 0 &&
			p.Order != nil && p.Order.Cmp(cp.N) == 0 && bytes.Equal(p.Base, base) &&
			(p.Cofactor == nil || p.Cofactor.Cmp(big.NewInt(1)) == 0) {
			return c.curve, bits, nil
		}
	}
	return nil, bits, nil
}

// describe is a short phrase naming the key, for a Detail.
func (k *PublicKeyInfo) describe() string {
	if k == nil {
		return "no key"
	}
	switch k.Algorithm {
	case KeyRSA:
		return "RSA " + strconv.Itoa(k.Bits)
	case KeyEC:
		return "EC " + k.Curve
	}
	return string(k.Algorithm)
}

// unsupportedDetail explains why a key cannot be computed with.
func (k *PublicKeyInfo) unsupportedDetail() string {
	switch k.Unsupported {
	case ReasonUnsupportedCurve:
		return fmt.Sprintf("the key is on %s, a curve the Go standard library does not implement; the signature cannot be checked here and is not taken as valid", k.Curve)
	default:
		return fmt.Sprintf("the key (%s) is of a kind this package does not compute with", k.describe())
	}
}
