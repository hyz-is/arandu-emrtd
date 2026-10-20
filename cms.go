package emrtd

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// The CMS SignedData of RFC 5652, as an EF.SOD and a CSCA master list carry
// it: one encapsulated content, the signer's certificates, one signer.

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type signedDataASN1 struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type signerInfoASN1 struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attributeASN1 struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// signedData is a parsed CMS SignedData.
type signedData struct {
	eContentType asn1.ObjectIdentifier
	eContent     []byte
	certificates []*Certificate
	signer       signerInfoASN1
	// digest is the signer's digest algorithm, or 0 when it is not one this
	// package implements.
	digest      crypto.Hash
	signingTime time.Time
	// attrs is the signed attributes by OID, first value each.
	attrs map[string][]byte
}

// parseSignedData parses a DER ContentInfo of type SignedData with exactly
// one signer.
func parseSignedData(der []byte) (*signedData, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, malformed("ContentInfo: %v", err)
	}
	if !padding(rest) {
		return nil, malformed("bytes after the ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, malformed("ContentInfo of type %s, not SignedData", ci.ContentType)
	}
	var sd signedDataASN1
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) > 0 {
		return nil, malformed("SignedData: %v", err)
	}
	out := &signedData{eContentType: sd.EncapContentInfo.EContentType}
	if len(sd.EncapContentInfo.EContent.Bytes) == 0 {
		return nil, malformed("SignedData without encapsulated content")
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &octets); err != nil || len(rest) > 0 {
		return nil, malformed("encapsulated content is not one OCTET STRING")
	}
	out.eContent = octets

	certs := sd.Certificates.Bytes
	for len(certs) > 0 {
		if len(out.certificates) >= maxCMSCerts {
			return nil, tooLarge("more than %d certificates", maxCMSCerts)
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(certs, &raw)
		if err != nil {
			return nil, malformed("certificate set: %v", err)
		}
		certs = rest
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			// Another CertificateChoices alternative; not an X.509 certificate.
			continue
		}
		c, err := ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}
		out.certificates = append(out.certificates, c)
	}

	if sd.SignerInfos.Tag != asn1.TagSet || sd.SignerInfos.Class != asn1.ClassUniversal {
		return nil, malformed("signerInfos is not a SET")
	}
	signers := sd.SignerInfos.Bytes
	var all []signerInfoASN1
	for len(signers) > 0 {
		if len(all) >= maxCMSSigners {
			return nil, tooLarge("more than %d signers", maxCMSSigners)
		}
		var si signerInfoASN1
		rest, err := asn1.Unmarshal(signers, &si)
		if err != nil {
			return nil, malformed("SignerInfo: %v", err)
		}
		all = append(all, si)
		signers = rest
	}
	if len(all) != 1 {
		return nil, malformed("%d signers where one was expected", len(all))
	}
	out.signer = all[0]
	out.digest = hashFromOID(out.signer.DigestAlgorithm.Algorithm)

	if len(out.signer.SignedAttrs.FullBytes) > 0 {
		attrs, err := parseAttributes(out.signer.SignedAttrs.Bytes)
		if err != nil {
			return nil, err
		}
		out.attrs = attrs
		if v, ok := attrs[oidAttrSigningTime.String()]; ok {
			var t time.Time
			if _, err := asn1.Unmarshal(v, &t); err == nil {
				out.signingTime = t.UTC()
			}
		}
	}
	return out, nil
}

// parseAttributes reads a SET OF Attribute into the first value of each
// type. A type present twice is malformed: which one was signed would be the
// reader's guess.
func parseAttributes(b []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	for len(b) > 0 {
		if len(out) >= 32 {
			return nil, tooLarge("more than 32 signed attributes")
		}
		var a attributeASN1
		rest, err := asn1.Unmarshal(b, &a)
		if err != nil {
			return nil, malformed("attribute: %v", err)
		}
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(a.Values.Bytes, &value); err != nil {
			return nil, malformed("attribute without a value")
		}
		key := a.Type.String()
		if _, dup := out[key]; dup {
			return nil, malformed("attribute %s twice", key)
		}
		out[key] = value.FullBytes
		b = rest
	}
	return out, nil
}

// findSigner finds the certificate the signer identifier names, among the
// CMS's own certificates and then the extra ones given.
func (sd *signedData) findSigner(extra []*Certificate) *Certificate {
	sid := sd.signer.SID
	match := func(c *Certificate) bool {
		if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
			return len(c.subjectKeyID) > 0 && bytes.Equal(c.subjectKeyID, sid.Bytes)
		}
		var ias issuerAndSerial
		if rest, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil || len(rest) > 0 || ias.Serial == nil {
			return false
		}
		if c.serial.Cmp(ias.Serial) != 0 {
			return false
		}
		if bytes.Equal(c.rawIssuer, ias.Issuer.FullBytes) {
			return true
		}
		a := canonicalName(c.rawIssuer)
		return a != "" && a == canonicalName(ias.Issuer.FullBytes)
	}
	for _, c := range sd.certificates {
		if match(c) {
			return c
		}
	}
	for _, c := range extra {
		if match(c) {
			return c
		}
	}
	return nil
}

// checkSigner checks the signer's signature with signer's key: the signed
// attributes must carry the content type and the digest of the encapsulated
// content, and the signature covers them. Without signed attributes, which
// ICAO Doc 9303 requires in an SOD, the signature covers the content, and the
// pass says so.
func (sd *signedData) checkSigner(signer *Certificate) sigResult {
	if sd.digest == 0 {
		return sigResult{OutcomeUnverifiable, ReasonUnsupportedHash, "digest algorithm " + sd.signer.DigestAlgorithm.Algorithm.String() + " is not implemented here"}
	}
	signed := sd.eContent
	note := Reason("")
	if sd.attrs != nil {
		var ctype asn1.ObjectIdentifier
		v, ok := sd.attrs[oidAttrContentType.String()]
		if !ok {
			return sigResult{OutcomeFailed, ReasonContentTypeMismatch, "the signed attributes carry no content type"}
		}
		if _, err := asn1.Unmarshal(v, &ctype); err != nil || !ctype.Equal(sd.eContentType) {
			return sigResult{OutcomeFailed, ReasonContentTypeMismatch, "the signed content type is not the encapsulated content's"}
		}
		var digest []byte
		v, ok = sd.attrs[oidAttrDigest.String()]
		if !ok {
			return sigResult{OutcomeFailed, ReasonMessageDigestMismatch, "the signed attributes carry no message digest"}
		}
		if _, err := asn1.Unmarshal(v, &digest); err != nil {
			return sigResult{OutcomeFailed, ReasonMessageDigestMismatch, "the message digest does not decode"}
		}
		h := sd.digest.New()
		h.Write(sd.eContent)
		if subtle.ConstantTimeCompare(digest, h.Sum(nil)) != 1 {
			return sigResult{OutcomeFailed, ReasonMessageDigestMismatch, "the signed message digest is not the digest of the encapsulated content"}
		}
		// The signature covers the attributes as a DER SET OF, not under the
		// implicit [0] they are carried with.
		signed = append([]byte{0x31}, sd.signer.SignedAttrs.FullBytes[1:]...)
	} else {
		note = ReasonNoSignedAttributes
	}
	res := checkSignature(signer.Key, sd.signer.SignatureAlgorithm, sd.digest, signed, sd.signer.Signature)
	if res.outcome == OutcomePassed && note != "" && res.reason == "" {
		res.reason = note
		res.detail = "the signature verifies over the content itself: the signer info has no signed attributes"
	}
	if res.outcome == OutcomePassed && sd.digest == crypto.SHA1 && res.reason == "" {
		res.reason = ReasonWeakHash
	}
	return res
}
