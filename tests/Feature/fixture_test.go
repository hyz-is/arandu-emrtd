package feature_test

// Synthetic eMRTD fixtures, generated in the test run.
//
// Every key is generated here, every certificate is issued here by a test
// CSCA of the fictitious state Utopia ("UTO"), and every data group holds
// invented data. Nothing is read from a real document, and nothing here may
// ever be replaced by bytes read from one.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	emrtd "github.com/hyz-is/arandu-emrtd"
)

var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidLDSSecurity    = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	oidMasterList     = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 2}
	oidMasterListEKU  = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 3}
	oidAA             = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 5}
	oidContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSASHA256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSASHA256      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSAPSS         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECPublicKey    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidBrainpoolP256  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidPKECDH         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 2}
	oidCAECDHAES128   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 2}
	oidPACEECDHGM128  = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2}
	oidECDSAPlainSHA2 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 3}
)

// The synthetic MRZ of the fixtures: an invented holder of Utopia.
const (
	mrzLine1 = "P<UTOSPECIMEN<<TESTE<SINTETICO<<<<<<<<<<<<<<"
	mrzDocNo = "XA0000017"
)

// evaluation is the time every fixture is examined at.
var evaluation = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// tlvEncode writes a BER-TLV data object with a definite length.
func tlvEncode(tag uint32, value []byte) []byte {
	var out []byte
	switch {
	case tag > 0xffff:
		out = append(out, byte(tag>>16), byte(tag>>8), byte(tag))
	case tag > 0xff:
		out = append(out, byte(tag>>8), byte(tag))
	default:
		out = append(out, byte(tag))
	}
	n := len(value)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, value...)
}

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return b
}

func set(content ...[]byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: bytes.Join(content, nil)}
}

func tagged(tag int, content ...[]byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: bytes.Join(content, nil)}
}

// mrzLine2 builds the second TD3 line with right check digits.
func mrzLine2(t testing.TB, docNo, birth, expiry string) string {
	t.Helper()
	cd := func(s string) string {
		d, err := emrtd.CheckDigit(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(rune('0' + d))
	}
	personal := "<<<<<<<<<<<<<<"
	l := docNo + cd(docNo) + "UTO" + birth + cd(birth) + "F" + expiry + cd(expiry) + personal + "<"
	return l + cd(l[0:10]+l[13:20]+l[21:43])
}

func printedMRZ(t testing.TB) string {
	return mrzLine1 + "\n" + mrzLine2(t, mrzDocNo, "900101", "310101") + "\n"
}

func buildDG1(t testing.TB) []byte {
	mrz := mrzLine1 + mrzLine2(t, mrzDocNo, "900101", "310101")
	return tlvEncode(0x61, tlvEncode(0x5f1f, []byte(mrz)))
}

var (
	jpegOnce  sync.Once
	jpegBytes []byte
)

// syntheticJPEG is an 8x8 gradient: an image, and no one's face.
func syntheticJPEG(t testing.TB) []byte {
	jpegOnce.Do(func() {
		img := image.NewGray(image.Rect(0, 0, 8, 8))
		for y := range 8 {
			for x := range 8 {
				img.SetGray(x, y, color.Gray{Y: uint8(x*16 + y*8)})
			}
		}
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, nil); err != nil {
			panic(err)
		}
		jpegBytes = buf.Bytes()
	})
	return jpegBytes
}

// syntheticJ2K is the JP2 signature box followed by filler: enough to be
// recognized as JPEG 2000, which is all this package does with it.
func syntheticJ2K() []byte {
	return append([]byte{0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a}, bytes.Repeat([]byte{0x42}, 32)...)
}

// buildDG2 wraps one image in an ISO/IEC 19794-5 version 010 facial record.
func buildDG2(image []byte, declared byte) []byte {
	var face bytes.Buffer
	blockLen := 20 + 12 + len(image)
	face.Write([]byte{byte(blockLen >> 24), byte(blockLen >> 16), byte(blockLen >> 8), byte(blockLen)})
	face.Write([]byte{0, 0})                    // feature points
	face.Write(make([]byte, 14))                // gender .. pose uncertainty
	face.Write([]byte{1, declared, 0, 8, 0, 8}) // image type, data type, width, height
	face.Write([]byte{1, 2, 0, 0, 0, 0})        // colour space, source, device, quality
	face.Write(image)
	var record bytes.Buffer
	recordLen := 14 + face.Len()
	record.WriteString("FAC\x00010\x00")
	record.Write([]byte{byte(recordLen >> 24), byte(recordLen >> 16), byte(recordLen >> 8), byte(recordLen)})
	record.Write([]byte{0, 1})
	record.Write(face.Bytes())
	bht := tlvEncode(0xa1, tlvEncode(0x87, []byte{0x01, 0x01}))
	bit := tlvEncode(0x7f60, append(bht, tlvEncode(0x5f2e, record.Bytes())...))
	group := tlvEncode(0x7f61, append(tlvEncode(0x02, []byte{1}), bit...))
	return tlvEncode(0x75, group)
}

type securityInfo struct {
	Protocol asn1.ObjectIdentifier
	Required asn1.RawValue
	Optional asn1.RawValue `asn1:"optional"`
}

func intValue(t testing.TB, v int) asn1.RawValue {
	return asn1.RawValue{FullBytes: mustMarshal(t, v)}
}

// buildDG14 holds one P-256 Chip Authentication key, its protocol and the
// ActiveAuthenticationInfo naming ecdsa-plain-SHA256.
func buildDG14(t testing.TB, caKey *ecdsa.PrivateKey, withAA bool) []byte {
	spki, err := x509.MarshalPKIXPublicKey(&caKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	infos := [][]byte{
		mustMarshal(t, securityInfo{Protocol: oidPKECDH, Required: asn1.RawValue{FullBytes: spki}}),
		mustMarshal(t, securityInfo{Protocol: oidCAECDHAES128, Required: intValue(t, 1)}),
		mustMarshal(t, securityInfo{Protocol: oidPACEECDHGM128, Required: intValue(t, 2), Optional: intValue(t, 12)}),
	}
	if withAA {
		infos = append(infos, mustMarshal(t, securityInfo{Protocol: oidAA, Required: intValue(t, 1),
			Optional: asn1.RawValue{FullBytes: mustMarshal(t, oidECDSAPlainSHA2)}}))
	}
	return tlvEncode(0x6e, mustMarshal(t, set(infos...)))
}

func buildCardAccess(t testing.TB, parameterID int) []byte {
	return mustMarshal(t, set(mustMarshal(t, securityInfo{Protocol: oidPACEECDHGM128, Required: intValue(t, 2), Optional: intValue(t, parameterID)})))
}

func buildDG15(t testing.TB, pub crypto.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return tlvEncode(0x6f, spki)
}

func buildCOM(groups ...byte) []byte {
	body := tlvEncode(0x5f01, []byte("0108"))
	body = append(body, tlvEncode(0x5f36, []byte("040000"))...)
	body = append(body, tlvEncode(0x5c, groups)...)
	return tlvEncode(0x60, body)
}

// authority is a key and the certificate that names it.
type authority struct {
	key  crypto.Signer
	cert *x509.Certificate
	der  []byte
}

var serials struct {
	sync.Mutex
	n int64
}

func nextSerial() *big.Int {
	serials.Lock()
	defer serials.Unlock()
	serials.n++
	return big.NewInt(0x1000 + serials.n)
}

func ecKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	rsaOnce sync.Once
	rsaKeys []*rsa.PrivateKey
)

// rsaKey returns one of a few RSA keys generated once per test binary, so
// the suite does not spend its time in key generation.
func rsaKey(t testing.TB, i int) *rsa.PrivateKey {
	rsaOnce.Do(func() {
		for _, bits := range []int{2048, 2048, 1024} {
			k, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				panic(err)
			}
			rsaKeys = append(rsaKeys, k)
		}
	})
	return rsaKeys[i]
}

func newCSCA(t testing.TB, cn string, key crypto.Signer) authority {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{Country: []string{"UT"}, Organization: []string{"Synthetic"}, CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{key: key, cert: cert, der: der}
}

func (a authority) issue(t testing.TB, cn string, key crypto.Signer, notBefore, notAfter time.Time, sigAlg x509.SignatureAlgorithm, mutate func(*x509.Certificate)) authority {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       nextSerial(),
		Subject:            pkix.Name{Country: []string{"UT"}, Organization: []string{"Synthetic"}, CommonName: cn},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: sigAlg,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, key.Public(), a.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{key: key, cert: cert, der: der}
}

func (a authority) documentSigner(t testing.TB, key crypto.Signer) authority {
	return a.issue(t, "Synthetic Document Signer", key,
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC), 0, nil)
}

// cmsOptions shape one signed CMS.
type cmsOptions struct {
	// noSignedAttrs signs the content itself.
	noSignedAttrs bool
	// digestOverride replaces the messageDigest attribute.
	digestOverride []byte
	// signatureOverride replaces the signature.
	signatureOverride []byte
	// pss signs an RSA key with RSASSA-PSS, salt 32.
	pss bool
	// extraCerts is carried besides the signer's.
	extraCerts [][]byte
	// noCerts leaves the signer's certificate out.
	noCerts     bool
	signingTime time.Time
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pssParams struct {
	Hash       algorithmIdentifier `asn1:"explicit,tag:0"`
	MGF        algorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength int                 `asn1:"explicit,tag:2"`
}

type issuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type encapContent struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

// signCMS builds a ContentInfo of SignedData over content, signed by signer
// whose certificate is signerDER.
func signCMS(t testing.TB, contentType asn1.ObjectIdentifier, content []byte, signer crypto.Signer, signerDER []byte, o cmsOptions) []byte {
	t.Helper()
	raw := rawCert(t, signerDER)

	digest := sha256.Sum256(content)
	sha256AI := algorithmIdentifier{Algorithm: oidSHA256}

	var signedAttrs asn1.RawValue
	toSign := content
	if !o.noSignedAttrs {
		md := digest[:]
		if o.digestOverride != nil {
			md = o.digestOverride
		}
		when := o.signingTime
		if when.IsZero() {
			when = time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
		}
		attrs := bytes.Join([][]byte{
			mustMarshal(t, attribute{Type: oidContentType, Values: set(mustMarshal(t, contentType))}),
			mustMarshal(t, attribute{Type: oidSigningTime, Values: set(mustMarshal(t, when))}),
			mustMarshal(t, attribute{Type: oidMessageDigest, Values: set(mustMarshal(t, md))}),
		}, nil)
		toSign = mustMarshal(t, set(attrs))
		signedAttrs = tagged(0, attrs)
	}

	var sigAlg algorithmIdentifier
	var sig []byte
	var err error
	h := sha256.Sum256(toSign)
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		sigAlg = algorithmIdentifier{Algorithm: oidECDSASHA256}
		sig, err = ecdsa.SignASN1(rand.Reader, k, h[:])
	case *rsa.PrivateKey:
		if o.pss {
			params := pssParams{
				Hash:       sha256AI,
				MGF:        algorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, sha256AI)}},
				SaltLength: 32,
			}
			sigAlg = algorithmIdentifier{Algorithm: oidRSAPSS, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, params)}}
			sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: 32})
		} else {
			sigAlg = algorithmIdentifier{Algorithm: oidRSASHA256}
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		}
	default:
		// A key this test cannot sign with: a placeholder signature.
		sigAlg = algorithmIdentifier{Algorithm: oidECDSASHA256}
		sig = bytes.Repeat([]byte{0x30}, 70)
	}
	if err != nil {
		t.Fatal(err)
	}
	if o.signatureOverride != nil {
		sig = o.signatureOverride
	}

	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: mustMarshal(t, issuerSerial{Issuer: asn1.RawValue{FullBytes: raw.issuer}, Serial: raw.serial})},
		DigestAlgorithm:    sha256AI,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
	}
	certs := [][]byte{signerDER}
	if o.noCerts {
		certs = nil
	}
	certs = append(certs, o.extraCerts...)

	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		Encap            encapContent
		Certificates     asn1.RawValue `asn1:"optional"`
		SignerInfos      asn1.RawValue
	}
	sd := signedData{
		Version:          3,
		DigestAlgorithms: set(mustMarshal(t, sha256AI)),
		Encap:            encapContent{Type: contentType, Content: tagged(0, mustMarshal(t, content))},
		SignerInfos:      set(mustMarshal(t, si)),
	}
	if len(certs) > 0 {
		sd.Certificates = tagged(0, certs...)
	}
	return mustMarshal(t, contentInfo{ContentType: oidSignedData, Content: tagged(0, mustMarshal(t, sd))})
}

type certParts struct {
	issuer []byte
	serial *big.Int
}

func rawCert(t testing.TB, der []byte) certParts {
	t.Helper()
	var outer struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatal(err)
	}
	rest := outer.TBS.Bytes
	var head asn1.RawValue
	if r, err := asn1.Unmarshal(rest, &head); err == nil && head.Class == asn1.ClassContextSpecific {
		rest = r
	}
	var serial *big.Int
	var alg, issuer asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &serial)
	rest, _ = asn1.Unmarshal(rest, &alg)
	_, _ = asn1.Unmarshal(rest, &issuer)
	return certParts{issuer: issuer.FullBytes, serial: serial}
}

type ldsSecurityObject struct {
	Version       int
	HashAlgorithm algorithmIdentifier
	Hashes        []dataGroupHash
}

type dataGroupHash struct {
	Number int
	Value  []byte
}

// buildSOD hashes the data groups with SHA-256 and signs the LDS security
// object with the Document Signer.
func buildSOD(t testing.TB, ds authority, groups map[int][]byte, o cmsOptions) []byte {
	t.Helper()
	lso := ldsSecurityObject{Version: 0, HashAlgorithm: algorithmIdentifier{Algorithm: oidSHA256}}
	for n := 1; n <= 16; n++ {
		if b, ok := groups[n]; ok {
			sum := sha256.Sum256(b)
			lso.Hashes = append(lso.Hashes, dataGroupHash{Number: n, Value: sum[:]})
		}
	}
	content := mustMarshal(t, lso)
	return tlvEncode(0x77, signCMS(t, oidLDSSecurity, content, ds.key, ds.der, o))
}

// passport is one complete synthetic chip read, with the keys behind it.
type passport struct {
	csca   authority
	ds     authority
	caKey  *ecdsa.PrivateKey
	aaKey  crypto.Signer
	input  emrtd.Input
	groups map[int][]byte
}

// newPassport builds a chip with DG1, DG2, DG14 and DG15 and an EC Active
// Authentication key, signed by a Document Signer of a fresh CSCA.
func newPassport(t testing.TB) *passport {
	t.Helper()
	csca := newCSCA(t, "Synthetic CSCA", ecKey(t))
	return newPassportUnder(t, csca, csca.documentSigner(t, ecKey(t)), nil)
}

func newPassportUnder(t testing.TB, csca, ds authority, aaKey crypto.Signer) *passport {
	t.Helper()
	p := &passport{csca: csca, ds: ds, caKey: ecKey(t), aaKey: aaKey}
	if p.aaKey == nil {
		p.aaKey = ecKey(t)
	}
	_, ecAA := p.aaKey.(*ecdsa.PrivateKey)
	p.groups = map[int][]byte{
		1:  buildDG1(t),
		2:  buildDG2(syntheticJPEG(t), 0),
		14: buildDG14(t, p.caKey, ecAA),
		15: buildDG15(t, p.aaKey.Public()),
	}
	p.input = emrtd.Input{
		COM:        buildCOM(0x61, 0x75, 0x6e, 0x6f),
		SOD:        buildSOD(t, ds, p.groups, cmsOptions{}),
		DataGroups: copyGroups(p.groups),
		CardAccess: buildCardAccess(t, 12),
		PrintedMRZ: printedMRZ(t),
	}
	return p
}

func copyGroups(g map[int][]byte) map[int][]byte {
	out := map[int][]byte{}
	for k, v := range g {
		out[k] = bytes.Clone(v)
	}
	return out
}

func (p *passport) trust(t testing.TB) *emrtd.TrustStore {
	t.Helper()
	ts := emrtd.NewTrustStore()
	if _, err := ts.AddCSCA(p.csca.der); err != nil {
		t.Fatal(err)
	}
	return ts
}

// respondAA answers a challenge as the chip would.
func (p *passport) respondAA(t testing.TB, challenge []byte) []byte {
	t.Helper()
	switch k := p.aaKey.(type) {
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256(challenge)
		r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		size := (k.Curve.Params().N.BitLen() + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	case *rsa.PrivateKey:
		return iso9796Sign(t, k, challenge, crypto.SHA1)
	}
	t.Fatal("no AA key")
	return nil
}

// iso9796Sign signs as an RSA chip does: ISO/IEC 9796-2 scheme 1, partial
// recovery, F = 6A || M1 || H(M1 || challenge) || trailer.
func iso9796Sign(t testing.TB, k *rsa.PrivateKey, challenge []byte, hash crypto.Hash) []byte {
	t.Helper()
	size := (k.N.BitLen() + 7) / 8
	trailer := []byte{0xbc}
	if hash != crypto.SHA1 {
		trailer = []byte{0x34, 0xcc}
	}
	hlen := hash.Size()
	m1 := make([]byte, size-1-hlen-len(trailer))
	if _, err := rand.Read(m1); err != nil {
		t.Fatal(err)
	}
	var digest []byte
	if hash == crypto.SHA1 {
		s := sha1.Sum(append(bytes.Clone(m1), challenge...))
		digest = s[:]
	} else {
		s := sha256.Sum256(append(bytes.Clone(m1), challenge...))
		digest = s[:]
	}
	f := append([]byte{0x6a}, m1...)
	f = append(f, digest...)
	f = append(f, trailer...)
	m := new(big.Int).SetBytes(f)
	s := new(big.Int).Exp(m, k.D, k.N)
	return s.FillBytes(make([]byte, size))
}

// tbsCertificate and friends build a certificate by hand, for keys
// crypto/x509 will not put in one.
type tbsCertificate struct {
	Version    int `asn1:"explicit,tag:0"`
	Serial     *big.Int
	Alg        algorithmIdentifier
	Issuer     asn1.RawValue
	Validity   validity
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Extensions asn1.RawValue
}

type validity struct {
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
}

type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// brainpoolSPKI is a SubjectPublicKeyInfo naming brainpoolP256r1 with a
// point this test does not need to be on the curve: nothing computes with it.
func brainpoolSPKI(t testing.TB) []byte {
	point := append([]byte{0x04}, bytes.Repeat([]byte{0x5a}, 64)...)
	return mustMarshal(t, struct {
		Alg algorithmIdentifier
		Key asn1.BitString
	}{
		Alg: algorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, oidBrainpoolP256)}},
		Key: asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
}

// handCertificate builds a certificate with any SubjectPublicKeyInfo, signed
// by signer (an ECDSA key) or, when signer is nil, with a placeholder.
func handCertificate(t testing.TB, subject, issuer pkix.Name, spki []byte, ca bool, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	ku := asn1.BitString{Bytes: []byte{0x80}, BitLength: 1} // digitalSignature
	exts := [][]byte{}
	if ca {
		ku = asn1.BitString{Bytes: []byte{0x06}, BitLength: 7} // keyCertSign, cRLSign
		bc := mustMarshal(t, struct {
			CA bool
		}{true})
		exts = append(exts, mustMarshal(t, extension{ID: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc}))
	}
	exts = append(exts, mustMarshal(t, extension{ID: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: mustMarshal(t, ku)}))
	tbs := tbsCertificate{
		Version:    2,
		Serial:     nextSerial(),
		Alg:        algorithmIdentifier{Algorithm: oidECDSASHA256},
		Issuer:     asn1.RawValue{FullBytes: mustMarshal(t, issuer.ToRDNSequence())},
		Validity:   validity{time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)},
		Subject:    asn1.RawValue{FullBytes: mustMarshal(t, subject.ToRDNSequence())},
		PublicKey:  asn1.RawValue{FullBytes: spki},
		Extensions: tagged(3, mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(exts, nil)})),
	}
	tbsDER := mustMarshal(t, tbs)
	sig := bytes.Repeat([]byte{0x30}, 70)
	if signer != nil {
		sum := sha256.Sum256(tbsDER)
		var err error
		if sig, err = ecdsa.SignASN1(rand.Reader, signer, sum[:]); err != nil {
			t.Fatal(err)
		}
	}
	return mustMarshal(t, struct {
		TBS asn1.RawValue
		Alg algorithmIdentifier
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, algorithmIdentifier{Algorithm: oidECDSASHA256}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

// placeholderSigner stands in for a key this test cannot sign with, a
// Brainpool one: signCMS writes a placeholder signature for it.
type placeholderSigner struct{}

func (placeholderSigner) Public() crypto.PublicKey { return nil }

func (placeholderSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return bytes.Repeat([]byte{0x30}, 70), nil
}

// buildMasterList signs a CSCA master list holding certs with the given
// signer.
func buildMasterList(t testing.TB, signer authority, certs ...[]byte) []byte {
	t.Helper()
	return signCMS(t, oidMasterList, masterListContent(t, certs...), signer.key, signer.der, cmsOptions{})
}

// masterListSigner issues a master list signer certificate under csca.
func masterListSigner(t testing.TB, csca authority) authority {
	return csca.issue(t, "Synthetic Master List Signer", ecKey(t),
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), 0,
		func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidMasterListEKU} })
}

// crlFor issues a CRL of csca revoking the given serials.
func crlFor(t testing.TB, csca authority, thisUpdate, nextUpdate time.Time, revoked ...*big.Int) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: thisUpdate.Add(-time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    nextSerial(),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, csca.cert, csca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// check fetches a check from the report, failing the test without it.
func check(t testing.TB, r *emrtd.Report, name emrtd.CheckName, file string) emrtd.Check {
	t.Helper()
	c, ok := r.Find(name, file)
	if !ok {
		t.Fatalf("the report has no %s check for %q; it has %+v", name, file, r.Checks)
	}
	return c
}

func want(t testing.TB, r *emrtd.Report, name emrtd.CheckName, file string, outcome emrtd.Outcome, reason emrtd.Reason) {
	t.Helper()
	c := check(t, r, name, file)
	if c.Outcome != outcome || c.Reason != reason {
		t.Errorf("%s %s = %s/%s (%s), want %s/%s", name, file, c.Outcome, c.Reason, c.Detail, outcome, reason)
	}
}

func masterListContent(t testing.TB, certs ...[]byte) []byte {
	return mustMarshal(t, struct {
		Version int
		Certs   asn1.RawValue
	}{0, set(certs...)})
}

func pkixName(cn string) pkix.Name {
	return pkix.Name{Country: []string{"UT"}, Organization: []string{"Synthetic"}, CommonName: cn}
}

func spkiOf(t testing.TB, pub crypto.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
