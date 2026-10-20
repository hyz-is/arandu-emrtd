package emrtd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1" // SHA-1 is registered so that older eMRTDs can be read; a SHA-1 pass carries ReasonWeakHash.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// sigScheme is how a signature is encoded and checked.
type sigScheme int

const (
	schemeUnknown sigScheme = iota
	schemePKCS1
	schemePSS
	schemeECDSADER
	schemeECDSAPlain
)

// sigResult is the outcome of one signature check and why.
type sigResult struct {
	outcome Outcome
	reason  Reason
	detail  string
}

type pssParameters struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// signatureScheme maps a signature AlgorithmIdentifier onto its scheme and
// hash. digest is the hash a CMS signer names apart, which a bare
// rsaEncryption or id-ecPublicKey signature algorithm takes as its own.
func signatureScheme(alg pkix.AlgorithmIdentifier, digest crypto.Hash) (sigScheme, crypto.Hash, int, Reason) {
	oid := alg.Algorithm
	switch {
	case oid.Equal(oidRSA):
		return schemePKCS1, digest, 0, ""
	case oid.Equal(oidRSASHA1):
		return schemePKCS1, crypto.SHA1, 0, ""
	case oid.Equal(oidRSASHA224):
		return schemePKCS1, crypto.SHA224, 0, ""
	case oid.Equal(oidRSASHA256):
		return schemePKCS1, crypto.SHA256, 0, ""
	case oid.Equal(oidRSASHA384):
		return schemePKCS1, crypto.SHA384, 0, ""
	case oid.Equal(oidRSASHA512):
		return schemePKCS1, crypto.SHA512, 0, ""
	case oid.Equal(oidRSAPSS):
		return pssScheme(alg.Parameters)
	case oid.Equal(oidECPublicKey):
		return schemeECDSADER, digest, 0, ""
	case oid.Equal(oidECDSASHA1):
		return schemeECDSADER, crypto.SHA1, 0, ""
	case oid.Equal(oidECDSASHA224):
		return schemeECDSADER, crypto.SHA224, 0, ""
	case oid.Equal(oidECDSASHA256):
		return schemeECDSADER, crypto.SHA256, 0, ""
	case oid.Equal(oidECDSASHA384):
		return schemeECDSADER, crypto.SHA384, 0, ""
	case oid.Equal(oidECDSASHA512):
		return schemeECDSADER, crypto.SHA512, 0, ""
	}
	if h := plainHash(oid); h != 0 {
		return schemeECDSAPlain, h, 0, ""
	}
	return schemeUnknown, 0, 0, ReasonUnsupportedAlgorithm
}

// pssScheme reads RSASSA-PSS-params (RFC 4055). The Go standard library
// generates the mask with the message hash, so a mask generation hash that
// differs is unsupported; so is a trailer other than 0xBC.
func pssScheme(raw asn1.RawValue) (sigScheme, crypto.Hash, int, Reason) {
	params := pssParameters{SaltLength: 20, TrailerField: 1}
	if len(raw.FullBytes) > 0 && raw.Tag != asn1.TagNull {
		if rest, err := asn1.Unmarshal(raw.FullBytes, &params); err != nil || len(rest) > 0 {
			return schemeUnknown, 0, 0, ReasonUnsupportedAlgorithm
		}
	}
	hash := crypto.SHA1
	if len(params.Hash.Algorithm) > 0 {
		hash = hashFromOID(params.Hash.Algorithm)
	}
	mgfHash := crypto.SHA1
	if len(params.MGF.Algorithm) > 0 {
		if !params.MGF.Algorithm.Equal(oidMGF1) {
			return schemeUnknown, 0, 0, ReasonUnsupportedAlgorithm
		}
		var inner pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &inner); err != nil {
			return schemeUnknown, 0, 0, ReasonUnsupportedAlgorithm
		}
		mgfHash = hashFromOID(inner.Algorithm)
	}
	if hash == 0 || mgfHash != hash || params.TrailerField != 1 || params.SaltLength < 0 || params.SaltLength > 1024 {
		return schemeUnknown, 0, 0, ReasonUnsupportedAlgorithm
	}
	return schemePSS, hash, params.SaltLength, ""
}

// checkSignature checks sig over message with key, under the signature
// algorithm alg. digest is the CMS signer's digest algorithm, or 0.
func checkSignature(key *PublicKeyInfo, alg pkix.AlgorithmIdentifier, digest crypto.Hash, message, sig []byte) sigResult {
	if key == nil {
		return sigResult{OutcomeUnverifiable, ReasonDocumentSignerMissing, "no key to check the signature with"}
	}
	scheme, hash, salt, reason := signatureScheme(alg, digest)
	if reason != "" || hash == 0 || !hash.Available() {
		return sigResult{OutcomeUnverifiable, ReasonUnsupportedAlgorithm, "signature algorithm " + alg.Algorithm.String() + " is not implemented here"}
	}
	if key.Key == nil {
		return sigResult{OutcomeUnverifiable, key.Unsupported, key.unsupportedDetail()}
	}
	h := hash.New()
	h.Write(message)
	sum := h.Sum(nil)

	var ok bool
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		if scheme != schemePKCS1 && scheme != schemePSS {
			return sigResult{OutcomeFailed, ReasonKeyAlgorithmMismatch, "an RSA key cannot check an ECDSA signature"}
		}
		if key.Bits < 1024 {
			return sigResult{OutcomeUnverifiable, ReasonRSAKeyTooSmall, "the Go standard library refuses RSA keys under 1024 bits"}
		}
		if scheme == schemePKCS1 {
			ok = rsa.VerifyPKCS1v15(pub, hash, sum, sig) == nil
		} else {
			ok = rsa.VerifyPSS(pub, hash, sum, sig, &rsa.PSSOptions{SaltLength: salt, Hash: hash}) == nil
		}
	case *ecdsa.PublicKey:
		switch scheme {
		case schemeECDSADER:
			ok = ecdsa.VerifyASN1(pub, sum, sig)
		case schemeECDSAPlain:
			ok = verifyPlain(pub, sum, sig)
		default:
			return sigResult{OutcomeFailed, ReasonKeyAlgorithmMismatch, "an EC key cannot check an RSA signature"}
		}
	default:
		return sigResult{OutcomeUnverifiable, ReasonUnsupportedKey, "the key is of a kind this package does not compute with"}
	}
	if !ok {
		return sigResult{OutcomeFailed, ReasonSignatureInvalid, "the signature does not verify with the key"}
	}
	if hash == crypto.SHA1 {
		return sigResult{OutcomePassed, ReasonWeakHash, "the signature verifies, over SHA-1"}
	}
	return sigResult{OutcomePassed, "", ""}
}

// verifyPlain checks an ECDSA signature in the plain format of BSI TR-03111:
// r and s as two big-endian integers of the order's length, concatenated.
func verifyPlain(pub *ecdsa.PublicKey, sum, sig []byte) bool {
	size := (pub.Curve.Params().N.BitLen() + 7) / 8
	if len(sig) != 2*size {
		return false
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(pub, sum, r, s)
}
