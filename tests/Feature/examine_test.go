package feature_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"image/jpeg"
	"strings"
	"testing"
	"time"

	emrtd "github.com/hyz-is/arandu-emrtd"
)

const (
	passedO       = emrtd.OutcomePassed
	failedO       = emrtd.OutcomeFailed
	notPresentO   = emrtd.OutcomeNotPresent
	unverifiableO = emrtd.OutcomeUnverifiable
)

func examine(p *passport, trust *emrtd.TrustStore) *emrtd.Report {
	return emrtd.Examine(p.input, trust, emrtd.Options{Time: evaluation})
}

func TestACompleteSyntheticChipPassesEveryCheckItCan(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	challenge, err := emrtd.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	p.input.ActiveAuthentication = &emrtd.ActiveAuthenticationResponse{Challenge: challenge, Signature: p.respondAA(t, challenge)}
	p.input.ChipAuthentication = &emrtd.ChipAuthenticationClaim{Protocol: oidCAECDHAES128.String(), KeyID: -1, Status: emrtd.DeviceCompleted}

	r := examine(p, p.trust(t))

	for _, file := range []string{emrtd.FileCOM, emrtd.FileSOD, "DG1", "DG2", "DG14", "DG15", emrtd.FileCardAccess} {
		want(t, r, emrtd.CheckFileStructure, file, passedO, "")
	}
	for _, file := range []string{"DG1", "DG2", "DG14", "DG15"} {
		want(t, r, emrtd.CheckDataGroupHash, file, passedO, "")
	}
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckDocumentSignerValidity, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckCSCAValidity, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckSigningTime, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckDocumentSignerRevocation, emrtd.FileSOD, notPresentO, emrtd.ReasonNoCRL)
	want(t, r, emrtd.CheckCOMConsistency, emrtd.FileCOM, passedO, "")
	want(t, r, emrtd.CheckMRZCheckDigits, "DG1", passedO, "")
	want(t, r, emrtd.CheckMRZPrintedComparison, "DG1", passedO, "")
	want(t, r, emrtd.CheckActiveAuthentication, "DG15", passedO, "")
	want(t, r, emrtd.CheckChipAuthenticationClaim, "DG14", passedO, emrtd.ReasonDeviceAssertedOnly)

	if r.MRZ == nil || r.MRZ.Format != emrtd.MRZTD3 || r.MRZ.DocumentNumber != mrzDocNo || r.MRZ.IssuingState != "UTO" ||
		r.MRZ.PrimaryIdentifier != "SPECIMEN" || r.MRZ.SecondaryIdentifier != "TESTE SINTETICO" {
		t.Errorf("MRZ = %+v", r.MRZ)
	}
	if r.SOD == nil || r.SOD.HashAlgorithm != "sha256" || len(r.SOD.DataGroupHashes) != 4 {
		t.Errorf("SOD = %+v", r.SOD)
	}
	if r.DocumentSigner == nil || r.CSCA == nil || r.CSCA.SHA256 != sha256Hex(p.csca.der) {
		t.Errorf("chain = %+v -> %+v", r.DocumentSigner, r.CSCA)
	}
	if len(r.Faces) != 1 || r.Faces[0].Format != emrtd.ImageJPEG || r.Faces[0].Width != 8 {
		t.Fatalf("faces = %+v", r.Faces)
	}
	if _, err := jpeg.Decode(bytes.NewReader(r.Faces[0].Data)); err != nil {
		t.Errorf("the extracted face image does not decode as JPEG: %v", err)
	}
	if r.CardAccess == nil || len(r.CardAccess.PACE) != 1 || r.CardAccess.PACE[0].Parameters != "P-256" || r.CardAccess.PACE[0].Mapping != "generic" {
		t.Errorf("card access = %+v", r.CardAccess)
	}
	if r.DG14 == nil || len(r.DG14.ChipAuthenticationKeys) != 1 || r.DG14.ChipAuthenticationKeys[0].Key.Curve != "P-256" {
		t.Errorf("DG14 = %+v", r.DG14)
	}
	for _, c := range r.Checks {
		if c.Outcome == "" {
			t.Errorf("check %+v has no outcome", c)
		}
	}
}

func TestAnAlteredDataGroupFailsItsHashAndOnlyIt(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	dg1 := p.input.DataGroups[1]
	dg1[len(dg1)-3] = 'Z' // one MRZ character
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckDataGroupHash, "DG1", failedO, emrtd.ReasonHashMismatch)
	want(t, r, emrtd.CheckDataGroupHash, "DG2", passedO, "")
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, "")
}

func TestADataGroupTheSODDoesNotHashFails(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.DataGroups[11] = tlvEncode(0x6b, tlvEncode(0x5f0e, []byte("SYNTHETIC")))
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckDataGroupHash, "DG11", failedO, emrtd.ReasonNotInSOD)
	want(t, r, emrtd.CheckFileStructure, "DG11", passedO, "")
}

func TestADataGroupNotProvidedIsNotPresent(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	delete(p.input.DataGroups, 2)
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckDataGroupHash, "DG2", notPresentO, emrtd.ReasonNotProvided)
}

func TestAFileUnderTheWrongNumberIsATagMismatch(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.DataGroups[3] = p.input.DataGroups[1]
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckFileStructure, "DG3", failedO, emrtd.ReasonTagMismatch)
}

func TestAnAlteredSignatureFails(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	sod := buildSOD(t, p.ds, p.groups, cmsOptions{signatureOverride: bytes.Repeat([]byte{0x01}, 64)})
	p.input.SOD = sod
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, failedO, emrtd.ReasonSignatureInvalid)
	// The hashes still match: they only mean anything with the signature.
	want(t, r, emrtd.CheckDataGroupHash, "DG1", passedO, "")
}

func TestASignedDigestOfOtherContentFails(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.SOD = buildSOD(t, p.ds, p.groups, cmsOptions{digestOverride: bytes.Repeat([]byte{0xab}, 32)})
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, failedO, emrtd.ReasonMessageDigestMismatch)
}

func TestASignatureWithoutSignedAttributesPassesAndSaysSo(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.SOD = buildSOD(t, p.ds, p.groups, cmsOptions{noSignedAttrs: true})
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, emrtd.ReasonNoSignedAttributes)
	want(t, r, emrtd.CheckSigningTime, emrtd.FileSOD, notPresentO, emrtd.ReasonNoSigningTime)
}

func TestADocumentSignerOfAnUntrustedCSCAIsUnverifiable(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	other := newCSCA(t, "Other Synthetic CSCA", ecKey(t))
	ts := emrtd.NewTrustStore()
	if _, err := ts.AddCSCA(other.der); err != nil {
		t.Fatal(err)
	}
	r := examine(p, ts)
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, unverifiableO, emrtd.ReasonCSCANotFound)
	want(t, r, emrtd.CheckCSCAValidity, emrtd.FileSOD, unverifiableO, emrtd.ReasonCSCANotFound)
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, "")
}

func TestACSCAWithTheRightNameAndAnotherKeyFails(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	impostor := newCSCA(t, "Synthetic CSCA", ecKey(t)) // same subject, other key
	ts := emrtd.NewTrustStore()
	if _, err := ts.AddCSCA(impostor.der); err != nil {
		t.Fatal(err)
	}
	r := examine(p, ts)
	c := check(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD)
	if c.Outcome == passedO {
		t.Fatalf("a CSCA with another key passed the chain: %+v", c)
	}
}

func TestNoTrustStoreLeavesTheChainUnverifiable(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	r := examine(p, nil)
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, unverifiableO, emrtd.ReasonNoTrustStore)
	want(t, r, emrtd.CheckDocumentSignerRevocation, emrtd.FileSOD, unverifiableO, emrtd.ReasonCSCANotFound)
}

func TestAnExpiredDocumentSignerFailsValidity(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	r := emrtd.Examine(p.input, p.trust(t), emrtd.Options{Time: time.Date(2033, 1, 1, 0, 0, 0, 0, time.UTC)})
	want(t, r, emrtd.CheckDocumentSignerValidity, emrtd.FileSOD, failedO, emrtd.ReasonExpired)
	want(t, r, emrtd.CheckCSCAValidity, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckSigningTime, emrtd.FileSOD, passedO, "")
}

func TestASigningTimeOutsideTheSignerValidityFails(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.SOD = buildSOD(t, p.ds, p.groups, cmsOptions{signingTime: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)})
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckSigningTime, emrtd.FileSOD, failedO, emrtd.ReasonNotYetValid)
}

func TestRevocationIsReadFromTheCSCAsCRL(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	this, next := evaluation.Add(-24*time.Hour), evaluation.Add(30*24*time.Hour)

	revoking := p.trust(t)
	if err := revoking.AddCRL(crlFor(t, p.csca, this, next, p.ds.cert.SerialNumber)); err != nil {
		t.Fatal(err)
	}
	want(t, examine(p, revoking), emrtd.CheckDocumentSignerRevocation, emrtd.FileSOD, failedO, emrtd.ReasonRevoked)

	clean := p.trust(t)
	if err := clean.AddCRL(crlFor(t, p.csca, this, next, nextSerial())); err != nil {
		t.Fatal(err)
	}
	want(t, examine(p, clean), emrtd.CheckDocumentSignerRevocation, emrtd.FileSOD, passedO, "")

	stale := p.trust(t)
	if err := stale.AddCRL(crlFor(t, p.csca, evaluation.Add(-60*24*time.Hour), evaluation.Add(-30*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	want(t, examine(p, stale), emrtd.CheckDocumentSignerRevocation, emrtd.FileSOD, passedO, emrtd.ReasonCRLStale)

	// A CRL under the CSCA's name and another key is not taken.
	forged := p.trust(t)
	impostor := newCSCA(t, "Synthetic CSCA", ecKey(t))
	if err := forged.AddCRL(crlFor(t, impostor, this, next, p.ds.cert.SerialNumber)); err != nil {
		t.Fatal(err)
	}
	want(t, examine(p, forged), emrtd.CheckDocumentSignerRevocation, emrtd.FileSOD, unverifiableO, emrtd.ReasonCRLSignature)
}

func TestRSAChainsWithPKCS1AndPSSPass(t *testing.T) {
	t.Parallel()
	csca := newCSCA(t, "Synthetic RSA CSCA", rsaKey(t, 0))
	ds := csca.issue(t, "Synthetic RSA Document Signer", rsaKey(t, 1),
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC), x509.SHA256WithRSAPSS, nil)
	p := newPassportUnder(t, csca, ds, rsaKey(t, 2))
	for _, pss := range []bool{false, true} {
		p.input.SOD = buildSOD(t, ds, p.groups, cmsOptions{pss: pss})
		r := examine(p, p.trust(t))
		want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, "")
		want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, passedO, "")
	}
}

func TestABrainpoolDocumentSignerIsUnverifiableNeverPassed(t *testing.T) {
	t.Parallel()
	csca := newCSCA(t, "Synthetic CSCA", ecKey(t))
	cscaName := pkix.Name{Country: []string{"UT"}, Organization: []string{"Synthetic"}, CommonName: "Synthetic CSCA"}
	dsName := pkix.Name{Country: []string{"UT"}, Organization: []string{"Synthetic"}, CommonName: "Synthetic Brainpool Signer"}
	der := handCertificate(t, dsName, cscaName, brainpoolSPKI(t), false, csca.key.(*ecdsa.PrivateKey))
	ds := authority{key: placeholderSigner{}, der: der}
	p := newPassportUnder(t, csca, ds, nil)

	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, unverifiableO, emrtd.ReasonUnsupportedCurve)
	// The CSCA is P-256, so the Document Signer's own certificate is checked.
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, passedO, "")
	if r.DocumentSigner == nil || r.DocumentSigner.Key.Curve != "brainpoolP256r1" || r.DocumentSigner.Key.Bits != 256 {
		t.Errorf("document signer key = %+v", r.DocumentSigner)
	}
	if c := check(t, r, emrtd.CheckSODSignature, emrtd.FileSOD); !strings.Contains(c.Detail, "brainpoolP256r1") {
		t.Errorf("the detail does not name the curve: %q", c.Detail)
	}
}

func TestABrainpoolCSCALeavesTheChainUnverifiable(t *testing.T) {
	t.Parallel()
	name := pkix.Name{Country: []string{"UT"}, Organization: []string{"Synthetic"}, CommonName: "Synthetic Brainpool CSCA"}
	cscaDER := handCertificate(t, name, name, brainpoolSPKI(t), true, nil)
	// The Document Signer's certificate names the Brainpool CSCA as issuer;
	// its signature is a placeholder nothing here can check.
	dsKey := ecKey(t)
	spki, err := x509.MarshalPKIXPublicKey(&dsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dsDER := handCertificate(t, pkix.Name{Country: []string{"UT"}, CommonName: "Synthetic Signer"}, name, spki, false, nil)
	p := newPassportUnder(t, authority{der: cscaDER}, authority{key: dsKey, der: dsDER}, nil)
	ts := emrtd.NewTrustStore()
	if _, err := ts.AddCSCA(cscaDER); err != nil {
		t.Fatal(err)
	}
	r := examine(p, ts)
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, unverifiableO, emrtd.ReasonUnsupportedCurve)
}

func TestTheDocumentSignerMayComeFromTheTrustStore(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.SOD = buildSOD(t, p.ds, p.groups, cmsOptions{noCerts: true})
	want(t, examine(p, p.trust(t)), emrtd.CheckSODSignature, emrtd.FileSOD, unverifiableO, emrtd.ReasonDocumentSignerMissing)

	ts := p.trust(t)
	if _, err := ts.AddDocumentSigner(p.ds.der); err != nil {
		t.Fatal(err)
	}
	r := examine(p, ts)
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, passedO, "")
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, passedO, "")
}

func TestNoSODAuthenticatesNothing(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.SOD = nil
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckFileStructure, emrtd.FileSOD, notPresentO, emrtd.ReasonNotProvided)
	want(t, r, emrtd.CheckDataGroupHash, "DG1", unverifiableO, emrtd.ReasonNotProvided)
	want(t, r, emrtd.CheckSODSignature, emrtd.FileSOD, notPresentO, emrtd.ReasonNotProvided)
}

func TestAPrintedMRZThatDiffersFailsTheComparison(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.PrintedMRZ = strings.Replace(printedMRZ(t), "SPECIMEN", "SPECIMAN", 1)
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckMRZPrintedComparison, "DG1", failedO, emrtd.ReasonFieldDiffers)
	for _, f := range r.MRZComparison {
		if (f.Field == emrtd.FieldPrimaryIdentifier) != (f.Outcome == failedO) {
			t.Errorf("comparison %+v", f)
		}
	}
}

func TestEFCOMThatDisagreesWithTheSODIsReported(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	p.input.COM = buildCOM(0x61, 0x75)
	want(t, examine(p, p.trust(t)), emrtd.CheckCOMConsistency, emrtd.FileCOM, failedO, emrtd.ReasonCOMDiffers)
}

func TestAJPEG2000FaceIsReturnedAndNotDecoded(t *testing.T) {
	t.Parallel()
	csca := newCSCA(t, "Synthetic CSCA", ecKey(t))
	p := newPassportUnder(t, csca, csca.documentSigner(t, ecKey(t)), nil)
	p.groups[2] = buildDG2(syntheticJ2K(), 1)
	p.input.DataGroups[2] = p.groups[2]
	p.input.SOD = buildSOD(t, p.ds, p.groups, cmsOptions{})
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckFileStructure, "DG2", passedO, emrtd.ReasonJPEG2000NotDecoded)
	want(t, r, emrtd.CheckDataGroupHash, "DG2", passedO, "")
	if len(r.Faces) != 1 || r.Faces[0].Format != emrtd.ImageJPEG2000 || r.Faces[0].DeclaredType != 1 || !bytes.Equal(r.Faces[0].Data, syntheticJ2K()) {
		t.Errorf("faces = %+v", r.Faces)
	}
}

func TestAReportSerializesWithoutTheFaceImageOrKeys(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	r := examine(p, p.trust(t))
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r.Faces[0].Data)
	if bytes.Contains(out, bytes.Trim(encoded, `"`)) {
		t.Error("the serialized report carries the face image")
	}
	if !bytes.Contains(out, []byte(`"outcome":"passed"`)) || !bytes.Contains(out, []byte(r.Faces[0].SHA256)) {
		t.Errorf("the serialized report lost its evidence: %s", out)
	}
}

func TestTheModuleExaminesWithItsTrustAndClock(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	m, err := emrtd.New(emrtd.Config{CSCACertificates: [][]byte{p.csca.der}, Now: func() time.Time { return evaluation }})
	if err != nil {
		t.Fatal(err)
	}
	if m.Name() != "emrtd" || m.TrustStore().Len() != 1 {
		t.Fatalf("module = %s with %d CSCAs", m.Name(), m.TrustStore().Len())
	}
	m.Routes(nil)
	r := m.Examine(p.input, emrtd.Options{})
	if !r.EvaluatedAt.Equal(evaluation) {
		t.Errorf("evaluated at %s", r.EvaluatedAt)
	}
	want(t, r, emrtd.CheckDocumentSignerChain, emrtd.FileSOD, passedO, "")

	if _, err := emrtd.New(emrtd.Config{CSCACertificates: [][]byte{[]byte("not a certificate")}}); err == nil {
		t.Error("New accepted a CSCA that does not parse")
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
