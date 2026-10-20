package emrtd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"math/big"
)

// ChallengeSize is the length of an Active Authentication challenge: ICAO Doc
// 9303 Part 11 has the terminal send eight random bytes.
const ChallengeSize = 8

// NewChallenge returns a fresh Active Authentication challenge from
// crypto/rand.
//
// The challenge is what makes the chip's answer prove possession now rather
// than replay an earlier one: the server issues it, keeps it with the session
// it belongs to, hands it to the device, and accepts one response for it,
// once. Keeping and expiring it is the application's.
func NewChallenge() ([]byte, error) {
	c := make([]byte, ChallengeSize)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	return c, nil
}

// ActiveAuthenticationResponse is what the device relays from the chip: the
// challenge it was given and the chip's signature over it.
type ActiveAuthenticationResponse struct {
	// Challenge is the server's challenge, as the server issued it. The
	// application passes its own copy, never one the device echoes back.
	Challenge []byte
	// Signature is the chip's INTERNAL AUTHENTICATE response.
	Signature []byte
}

// ISO/IEC 10118 hash identifiers of an ISO/IEC 9796-2 trailer 0x..CC.
var iso9796Hashes = map[byte]crypto.Hash{
	0x33: crypto.SHA1,
	0x34: crypto.SHA256,
	0x35: crypto.SHA512,
	0x36: crypto.SHA384,
	0x38: crypto.SHA224,
}

// ExamineActiveAuthentication checks the chip's Active Authentication
// signature over the server's challenge with the DG15 key (ICAO Doc 9303
// Part 11, 6.1).
//
// An RSA key signs with ISO/IEC 9796-2 digital signature scheme 1 and partial
// message recovery: the recovered representative is 6A || M1 || H || trailer,
// and H must be the hash of M1 followed by the challenge. An EC key signs the
// hash of the challenge with ECDSA in the plain format of BSI TR-03111, under
// the hash the ActiveAuthenticationInfo of DG14 names; info may be nil for an
// RSA key.
//
// The outcome is about the signature alone. Whether the key is the chip's is
// what Passive Authentication of DG15 says, and Examine combines the two.
func ExamineActiveAuthentication(key *PublicKeyInfo, info *ActiveAuthenticationInfo, challenge, signature []byte) Check {
	const name = CheckActiveAuthentication
	file := FileName(15)
	if key == nil {
		return notPresent(name, file, ReasonNotProvided, "no DG15 key")
	}
	if len(challenge) != ChallengeSize {
		return unverifiable(name, file, ReasonChallengeLength, "the challenge is not eight bytes")
	}
	if key.Key == nil {
		return unverifiable(name, file, key.Unsupported, key.unsupportedDetail())
	}
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		return checkISO9796(pub, challenge, signature)
	case *ecdsa.PublicKey:
		if info == nil || plainHash(info.oid) == 0 {
			return unverifiable(name, file, ReasonAAAlgorithmUnknown,
				"an EC Active Authentication needs the ecdsa-plain signature algorithm of DG14's ActiveAuthenticationInfo")
		}
		hash := plainHash(info.oid)
		h := hash.New()
		h.Write(challenge)
		sum := h.Sum(nil)
		ok := verifyPlain(pub, sum, signature)
		if !ok {
			// Some chips answer in the X9.62 DER form instead.
			ok = ecdsa.VerifyASN1(pub, sum, signature)
		}
		if !ok {
			return failed(name, file, ReasonSignatureInvalid, "the chip's signature over the challenge does not verify with the DG15 key")
		}
		if hash == crypto.SHA1 {
			return passed(name, file, ReasonWeakHash, "the chip's signature over the challenge verifies, over SHA-1")
		}
		return passed(name, file, "", "")
	}
	return unverifiable(name, file, ReasonUnsupportedKey, "the DG15 key is of a kind this package does not compute with")
}

func checkISO9796(pub *rsa.PublicKey, challenge, signature []byte) Check {
	const name = CheckActiveAuthentication
	file := FileName(15)
	if pub.N.BitLen() < 1024 {
		return unverifiable(name, file, ReasonRSAKeyTooSmall, "the DG15 RSA key is under 1024 bits")
	}
	size := (pub.N.BitLen() + 7) / 8
	if len(signature) == 0 || len(signature) > size {
		return failed(name, file, ReasonSignatureInvalid, "the signature is not of the key's length")
	}
	s := new(big.Int).SetBytes(signature)
	if s.Cmp(pub.N) >= 0 {
		return failed(name, file, ReasonSignatureInvalid, "the signature is not below the modulus")
	}
	m := new(big.Int).Exp(s, big.NewInt(int64(pub.E)), pub.N)
	// ISO/IEC 9796-2 lets the signer send the complement of the
	// representative; both are tried, and of two failures the one that got
	// past the header is the one that says what is wrong.
	direct := recoverISO9796(m, size, challenge)
	if direct.Outcome == OutcomePassed {
		return direct
	}
	complement := recoverISO9796(new(big.Int).Sub(pub.N, m), size, challenge)
	if complement.Outcome == OutcomePassed || direct.Reason == ReasonISO9796Header && complement.Reason != ReasonISO9796Header {
		return complement
	}
	return direct
}

func recoverISO9796(m *big.Int, size int, challenge []byte) Check {
	const name = CheckActiveAuthentication
	file := FileName(15)
	f := m.FillBytes(make([]byte, size))
	for len(f) > 0 && f[0] == 0 {
		f = f[1:]
	}
	if len(f) < 4 || f[0] != 0x6a {
		return failed(name, file, ReasonISO9796Header, "the recovered representative does not open with 6A (partial message recovery)")
	}
	var hash crypto.Hash
	trailer := 1
	switch f[len(f)-1] {
	case 0xbc:
		hash = crypto.SHA1
	case 0xcc:
		trailer = 2
		hash = iso9796Hashes[f[len(f)-2]]
		if hash == 0 {
			return unverifiable(name, file, ReasonUnsupportedHash, "the trailer names a hash this package does not implement")
		}
	default:
		return failed(name, file, ReasonISO9796Trailer, "the recovered representative ends with neither BC nor CC")
	}
	hlen := hash.Size()
	if len(f) < 1+hlen+trailer {
		return failed(name, file, ReasonISO9796Header, "the representative is shorter than its hash")
	}
	digest := f[len(f)-trailer-hlen : len(f)-trailer]
	m1 := f[1 : len(f)-trailer-hlen]
	h := hash.New()
	h.Write(m1)
	h.Write(challenge)
	if subtle.ConstantTimeCompare(digest, h.Sum(nil)) != 1 {
		return failed(name, file, ReasonSignatureInvalid, "the recovered hash is not the hash of the recovered message and the challenge")
	}
	if hash == crypto.SHA1 {
		return passed(name, file, ReasonWeakHash, "the chip's signature over the challenge verifies, over SHA-1")
	}
	return passed(name, file, "", "")
}
