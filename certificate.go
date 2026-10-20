package emrtd

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"time"
)

// Certificate is an X.509 certificate of the eMRTD PKI: a CSCA, a Document
// Signer, a master list signer.
//
// It is parsed here rather than by crypto/x509, which refuses a certificate
// whose key is on a curve it does not implement. Many CSCAs and Document
// Signers use Brainpool; parsed here, such a certificate is still named,
// dated and placed in its chain, and only the checks that need its key are
// unverifiable.
type Certificate struct {
	// Subject and Issuer are the distinguished names in RFC 2253 form.
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	// SerialNumber is the serial number in hexadecimal.
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	// SubjectKeyID and AuthorityKeyID are the key identifier extensions in
	// hexadecimal, or empty.
	SubjectKeyID   string `json:"subject_key_id,omitempty"`
	AuthorityKeyID string `json:"authority_key_id,omitempty"`
	// SignatureAlgorithm is the OID the certificate is signed under.
	SignatureAlgorithm string `json:"signature_algorithm"`
	// Key is the certificate's public key.
	Key *PublicKeyInfo `json:"key"`
	// SHA256 is the hex SHA-256 of the certificate DER, its fingerprint.
	SHA256 string `json:"sha256"`
	// Raw is the certificate DER.
	Raw []byte `json:"-"`

	rawTBS       []byte
	rawSubject   []byte
	rawIssuer    []byte
	sigAlg       pkix.AlgorithmIdentifier
	signature    []byte
	serial       *big.Int
	subjectKeyID []byte
	authKeyID    []byte
	// ca is 1 when basicConstraints says cA, 0 when it says not, -1 when
	// the extension is absent.
	ca int
	// keyUsage is the keyUsage bits, or -1 when the extension is absent.
	keyUsage  int
	extKeyUse []asn1.ObjectIdentifier
}

// The keyUsage bits this package reads (RFC 5280 4.2.1.3).
const (
	keyUsageDigitalSignature = 1 << 0
	keyUsageCertSign         = 1 << 5
	keyUsageCRLSign          = 1 << 6
)

type rawCertificate struct {
	TBS                asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           struct {
		NotBefore time.Time
		NotAfter  time.Time
	}
	Subject         asn1.RawValue
	PublicKey       asn1.RawValue
	IssuerUniqueID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions      []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// ParseCertificate parses one certificate DER.
func ParseCertificate(der []byte) (*Certificate, error) {
	if len(der) > MaxFileSize {
		return nil, tooLarge("certificate of %d bytes", len(der))
	}
	var outer rawCertificate
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, malformed("certificate: %v", err)
	}
	if len(rest) > 0 {
		return nil, malformed("bytes after the certificate")
	}
	var tbs tbsCertificate
	if rest, err := asn1.Unmarshal(outer.TBS.FullBytes, &tbs); err != nil || len(rest) > 0 {
		return nil, malformed("TBSCertificate: %v", err)
	}
	if tbs.SerialNumber == nil {
		return nil, malformed("certificate without a serial number")
	}
	if !tbs.SignatureAlgorithm.Algorithm.Equal(outer.SignatureAlgorithm.Algorithm) ||
		!bytes.Equal(tbs.SignatureAlgorithm.Parameters.FullBytes, outer.SignatureAlgorithm.Parameters.FullBytes) {
		return nil, malformed("the certificate names two signature algorithms")
	}
	key, err := ParsePublicKeyInfo(tbs.PublicKey.FullBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	c := &Certificate{
		Subject:            nameString(tbs.Subject.FullBytes),
		Issuer:             nameString(tbs.Issuer.FullBytes),
		SerialNumber:       tbs.SerialNumber.Text(16),
		NotBefore:          tbs.Validity.NotBefore.UTC(),
		NotAfter:           tbs.Validity.NotAfter.UTC(),
		SignatureAlgorithm: outer.SignatureAlgorithm.Algorithm.String(),
		Key:                key,
		SHA256:             hex.EncodeToString(sum[:]),
		Raw:                bytes.Clone(der),
		rawTBS:             outer.TBS.FullBytes,
		rawSubject:         tbs.Subject.FullBytes,
		rawIssuer:          tbs.Issuer.FullBytes,
		sigAlg:             outer.SignatureAlgorithm,
		signature:          outer.Signature.RightAlign(),
		serial:             tbs.SerialNumber,
		ca:                 -1,
		keyUsage:           -1,
	}
	if err := c.readExtensions(tbs.Extensions); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Certificate) readExtensions(exts []pkix.Extension) error {
	for _, e := range exts {
		switch {
		case e.Id.Equal(oidExtSubjectKeyID):
			var id []byte
			if _, err := asn1.Unmarshal(e.Value, &id); err != nil {
				return malformed("subjectKeyIdentifier")
			}
			c.subjectKeyID = id
			c.SubjectKeyID = hex.EncodeToString(id)
		case e.Id.Equal(oidExtAuthorityKeyID):
			var aki struct {
				ID asn1.RawValue `asn1:"optional,tag:0"`
			}
			if _, err := asn1.Unmarshal(e.Value, &aki); err != nil {
				return malformed("authorityKeyIdentifier")
			}
			if len(aki.ID.Bytes) > 0 {
				c.authKeyID = aki.ID.Bytes
				c.AuthorityKeyID = hex.EncodeToString(aki.ID.Bytes)
			}
		case e.Id.Equal(oidExtBasicConstr):
			var bc struct {
				CA      bool `asn1:"optional"`
				PathLen int  `asn1:"optional,default:-1"`
			}
			if _, err := asn1.Unmarshal(e.Value, &bc); err != nil {
				return malformed("basicConstraints")
			}
			c.ca = 0
			if bc.CA {
				c.ca = 1
			}
		case e.Id.Equal(oidExtKeyUsage):
			var bits asn1.BitString
			if _, err := asn1.Unmarshal(e.Value, &bits); err != nil {
				return malformed("keyUsage")
			}
			usage := 0
			for i := range min(bits.BitLength, 9) {
				if bits.At(i) != 0 {
					usage |= 1 << i
				}
			}
			c.keyUsage = usage
		case e.Id.Equal(oidExtExtKeyUsage):
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(e.Value, &oids); err != nil {
				return malformed("extKeyUsage")
			}
			c.extKeyUse = oids
		}
	}
	return nil
}

// nameString is a distinguished name in RFC 2253 form, or its hex when it
// does not decode.
func nameString(der []byte) string {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) > 0 {
		return "#" + hex.EncodeToString(der)
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String()
}

// canonicalName is a distinguished name compared as RFC 5280 7.1 asks for
// the common cases: attribute by attribute, case-folded and with blanks
// collapsed. Issuers write the same name with different string types more
// often than an eMRTD reader would like; a byte comparison would then find
// no CSCA.
func canonicalName(der []byte) string {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) > 0 {
		return ""
	}
	var parts []string
	for _, set := range rdn {
		var atvs []string
		for _, atv := range set {
			v, ok := atv.Value.(string)
			if !ok {
				return ""
			}
			atvs = append(atvs, atv.Type.String()+"="+strings.Join(strings.Fields(strings.ToLower(v)), " "))
		}
		slices.Sort(atvs)
		parts = append(parts, strings.Join(atvs, "+"))
	}
	return strings.Join(parts, ",")
}

// issuedBy reports whether issuer's name is c's issuer name and, when both
// carry key identifiers, whether they agree.
func (c *Certificate) issuedBy(issuer *Certificate) bool {
	if !bytes.Equal(c.rawIssuer, issuer.rawSubject) {
		a, b := canonicalName(c.rawIssuer), canonicalName(issuer.rawSubject)
		if a == "" || a != b {
			return false
		}
	}
	if len(c.authKeyID) > 0 && len(issuer.subjectKeyID) > 0 && !bytes.Equal(c.authKeyID, issuer.subjectKeyID) {
		return false
	}
	return true
}

// signedBy checks c's signature with issuer's key.
func (c *Certificate) signedBy(issuer *Certificate) sigResult {
	return checkSignature(issuer.Key, c.sigAlg, 0, c.rawTBS, c.signature)
}

// validAt reports how t lies against the certificate's validity.
func (c *Certificate) validAt(t time.Time) Reason {
	switch {
	case t.Before(c.NotBefore):
		return ReasonNotYetValid
	case t.After(c.NotAfter):
		return ReasonExpired
	}
	return ""
}
