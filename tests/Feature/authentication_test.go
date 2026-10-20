package feature_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
	"time"

	emrtd "github.com/hyz-is/arandu-emrtd"
)

func aaPassport(t *testing.T, aaKey crypto.Signer) *passport {
	t.Helper()
	csca := newCSCA(t, "Synthetic CSCA", ecKey(t))
	return newPassportUnder(t, csca, csca.documentSigner(t, ecKey(t)), aaKey)
}

func TestRSAActiveAuthenticationWithISO9796Passes(t *testing.T) {
	t.Parallel()
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		for i, key := range []*rsa.PrivateKey{rsaKey(t, 2), rsaKey(t, 0)} {
			p := aaPassport(t, key)
			challenge, err := emrtd.NewChallenge()
			if err != nil {
				t.Fatal(err)
			}
			p.input.ActiveAuthentication = &emrtd.ActiveAuthenticationResponse{Challenge: challenge, Signature: iso9796Sign(t, key, challenge, hash)}
			r := examine(p, p.trust(t))
			reason := emrtd.Reason("")
			if hash == crypto.SHA1 {
				reason = emrtd.ReasonWeakHash
			}
			want(t, r, emrtd.CheckActiveAuthentication, "DG15", passedO, reason)
			if r.ActiveAuthenticationKey == nil || r.ActiveAuthenticationKey.Algorithm != emrtd.KeyRSA {
				t.Errorf("key %d: %+v", i, r.ActiveAuthenticationKey)
			}
		}
	}
}

func TestActiveAuthenticationOverAnotherChallengeFails(t *testing.T) {
	t.Parallel()
	for _, key := range []crypto.Signer{rsaKey(t, 2), ecKey(t)} {
		p := aaPassport(t, key)
		issued, _ := emrtd.NewChallenge()
		replayed, _ := emrtd.NewChallenge()
		p.input.ActiveAuthentication = &emrtd.ActiveAuthenticationResponse{Challenge: issued, Signature: p.respondAA(t, replayed)}
		want(t, examine(p, p.trust(t)), emrtd.CheckActiveAuthentication, "DG15", failedO, emrtd.ReasonSignatureInvalid)
	}
}

func TestActiveAuthenticationWithAKeyPassiveAuthenticationDidNotCoverIsUnverifiable(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	// The device swaps DG15 for a key of its own and signs with it.
	other := ecKey(t)
	p.aaKey = other
	p.input.DataGroups[15] = buildDG15(t, other.Public())
	challenge, _ := emrtd.NewChallenge()
	p.input.ActiveAuthentication = &emrtd.ActiveAuthenticationResponse{Challenge: challenge, Signature: p.respondAA(t, challenge)}
	r := examine(p, p.trust(t))
	want(t, r, emrtd.CheckDataGroupHash, "DG15", failedO, emrtd.ReasonHashMismatch)
	want(t, r, emrtd.CheckActiveAuthentication, "DG15", unverifiableO, emrtd.ReasonKeyNotAuthenticated)
}

func TestECActiveAuthenticationNeedsDG14sAlgorithm(t *testing.T) {
	t.Parallel()
	key := ecKey(t)
	pub, err := emrtd.ParsePublicKeyInfo(spkiOf(t, key.Public()))
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := emrtd.NewChallenge()
	c := emrtd.ExamineActiveAuthentication(pub, nil, challenge, bytes.Repeat([]byte{1}, 64))
	if c.Outcome != unverifiableO || c.Reason != emrtd.ReasonAAAlgorithmUnknown {
		t.Errorf("EC AA without DG14 = %+v", c)
	}
	c = emrtd.ExamineActiveAuthentication(pub, nil, []byte{1, 2, 3}, nil)
	if c.Outcome != unverifiableO || c.Reason != emrtd.ReasonChallengeLength {
		t.Errorf("short challenge = %+v", c)
	}
	c = emrtd.ExamineActiveAuthentication(nil, nil, challenge, nil)
	if c.Outcome != notPresentO {
		t.Errorf("no key = %+v", c)
	}
}

func TestAGarbageRSAResponseFailsWithoutPanicking(t *testing.T) {
	t.Parallel()
	key := rsaKey(t, 2)
	pub, err := emrtd.ParsePublicKeyInfo(spkiOf(t, key.Public()))
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := emrtd.NewChallenge()
	for _, sig := range [][]byte{nil, {0}, bytes.Repeat([]byte{0xff}, 128), bytes.Repeat([]byte{0xff}, 300), bytes.Repeat([]byte{0x01}, 128)} {
		if c := emrtd.ExamineActiveAuthentication(pub, nil, challenge, sig); c.Outcome == passedO {
			t.Errorf("garbage %x passed", sig)
		}
	}
}

func TestChipAuthenticationClaimsAreHeldAgainstDG14(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	claim := func(protocol string, status emrtd.DeviceStatus) *emrtd.ChipAuthenticationClaim {
		return &emrtd.ChipAuthenticationClaim{Protocol: protocol, KeyID: -1, Status: status}
	}

	p.input.ChipAuthentication = claim(oidCAECDHAES128.String(), emrtd.DeviceFailed)
	want(t, examine(p, p.trust(t)), emrtd.CheckChipAuthenticationClaim, "DG14", failedO, emrtd.ReasonDeviceReportedFailure)

	p.input.ChipAuthentication = claim("0.4.0.127.0.7.2.2.3.2.4", emrtd.DeviceCompleted)
	want(t, examine(p, p.trust(t)), emrtd.CheckChipAuthenticationClaim, "DG14", failedO, emrtd.ReasonProtocolNotInDG14)

	p.input.ChipAuthentication = claim(oidCAECDHAES128.String(), "maybe")
	want(t, examine(p, p.trust(t)), emrtd.CheckChipAuthenticationClaim, "DG14", unverifiableO, emrtd.ReasonUnknownDeviceStatus)

	p.input.ChipAuthentication = nil
	want(t, examine(p, p.trust(t)), emrtd.CheckChipAuthenticationClaim, "DG14", notPresentO, emrtd.ReasonNotProvided)

	// A DG14 that does not hash to the SOD's value can name any key.
	p.input.ChipAuthentication = claim(oidCAECDHAES128.String(), emrtd.DeviceCompleted)
	p.input.DataGroups[14] = buildDG14(t, ecKey(t), true)
	want(t, examine(p, p.trust(t)), emrtd.CheckChipAuthenticationClaim, "DG14", unverifiableO, emrtd.ReasonKeyNotAuthenticated)
}

func TestAMasterListIsParsedCheckedAndLoaded(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	other := newCSCA(t, "Other Synthetic CSCA", ecKey(t))
	signer := masterListSigner(t, p.csca)
	ml := buildMasterList(t, signer, p.csca.der, other.der)

	parsed, err := emrtd.ParseMasterList(ml)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Certificates) != 2 || parsed.Skipped != 0 || parsed.Signature.Outcome != passedO {
		t.Fatalf("master list = %+v", parsed)
	}
	anchor, err := emrtd.ParseCertificate(p.csca.der)
	if err != nil {
		t.Fatal(err)
	}
	if c := parsed.CheckSigner([]*emrtd.Certificate{anchor}, evaluation); c.Outcome != passedO || c.Reason != "" {
		t.Errorf("signer under the anchor = %+v", c)
	}
	if c := parsed.CheckSigner(nil, evaluation); c.Outcome != passedO || c.Reason != emrtd.ReasonMasterListSignerNoAnch {
		t.Errorf("signer under the list itself = %+v", c)
	}
	otherAnchor, _ := emrtd.ParseCertificate(other.der)
	if c := parsed.CheckSigner([]*emrtd.Certificate{otherAnchor}, evaluation); c.Outcome == passedO {
		t.Errorf("signer under an unrelated anchor passed: %+v", c)
	}
	if c := parsed.CheckSigner([]*emrtd.Certificate{anchor}, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)); c.Outcome != failedO || c.Reason != emrtd.ReasonExpired {
		t.Errorf("expired signer = %+v", c)
	}

	m, err := emrtd.New(emrtd.Config{MasterLists: [][]byte{ml}, MasterListAnchors: [][]byte{p.csca.der}, Now: func() time.Time { return evaluation }})
	if err != nil {
		t.Fatal(err)
	}
	if m.TrustStore().Len() != 2 {
		t.Errorf("trust store holds %d CSCAs", m.TrustStore().Len())
	}
	want(t, m.Examine(p.input, emrtd.Options{}), emrtd.CheckDocumentSignerChain, emrtd.FileSOD, passedO, "")

	if _, err := emrtd.New(emrtd.Config{MasterLists: [][]byte{ml}, MasterListAnchors: [][]byte{other.der}, Now: func() time.Time { return evaluation }}); err == nil {
		t.Error("New accepted a master list whose signer no anchor issued")
	}
}

func TestAMasterListWithABadSignatureIsRefused(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	signer := masterListSigner(t, p.csca)
	ml := buildMasterList(t, signer, p.csca.der)
	// Flip one byte of a certificate inside the signed content.
	i := bytes.Index(ml, p.csca.der[40:60])
	ml[i] ^= 0x01
	parsed, err := emrtd.ParseMasterList(ml)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signature.Outcome != failedO {
		t.Fatalf("signature = %+v", parsed.Signature)
	}
	if _, err := emrtd.New(emrtd.Config{MasterLists: [][]byte{ml}, PinnedMasterListSHA256: []string{parsed.SHA256}}); err == nil {
		t.Error("New accepted a master list whose signature fails, because it was pinned")
	}
}

func TestAnUnverifiableMasterListNeedsItsDigestPinned(t *testing.T) {
	t.Parallel()
	p := newPassport(t)
	csca := p.csca
	// A signer on Brainpool: the list's signature cannot be checked here.
	spki := brainpoolSPKI(t)
	signerName := pkixName("Synthetic Brainpool List Signer")
	signerDER := handCertificate(t, signerName, pkixName("Synthetic CSCA"), spki, false, csca.key.(*ecdsa.PrivateKey))
	content := masterListContent(t, csca.der)
	ml := signCMS(t, oidMasterList, content, placeholderSigner{}, signerDER, cmsOptions{})

	parsed, err := emrtd.ParseMasterList(ml)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signature.Outcome != unverifiableO || parsed.Signature.Reason != emrtd.ReasonUnsupportedCurve {
		t.Fatalf("signature = %+v", parsed.Signature)
	}
	if _, err := emrtd.New(emrtd.Config{MasterLists: [][]byte{ml}}); err == nil {
		t.Error("New accepted an unverifiable master list that is not pinned")
	}
	m, err := emrtd.New(emrtd.Config{MasterLists: [][]byte{ml}, PinnedMasterListSHA256: []string{parsed.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	if m.TrustStore().Len() != 1 {
		t.Errorf("trust store holds %d CSCAs", m.TrustStore().Len())
	}
}
