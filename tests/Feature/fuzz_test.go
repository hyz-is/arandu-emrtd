package feature_test

// The parsers take bytes from a device the server does not control. These
// fuzz targets hold that none of them panics, whatever it is given, and that
// Examine answers only the four outcomes. `go test` runs them over their seed
// corpus; `go test -fuzz=<name>` explores further.

import (
	"testing"

	emrtd "github.com/hyz-is/arandu-emrtd"
)

func FuzzParseSOD(f *testing.F) {
	p := newPassport(f)
	f.Add(p.input.SOD)
	f.Add([]byte{0x77, 0x80, 0x30, 0x80})
	f.Add([]byte{0x77, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = emrtd.ParseSOD(b) })
}

func FuzzParseDG1(f *testing.F) {
	f.Add(buildDG1(f))
	f.Add(tlvEncode(0x61, tlvEncode(0x5f1f, []byte("I<UTO"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := emrtd.ParseDG1(b)
		if err == nil && (m == nil || len(m.CheckDigits) == 0) {
			t.Fatal("a parsed MRZ has no check digits")
		}
	})
}

func FuzzParseMRZ(f *testing.F) {
	f.Add(printedMRZ(f))
	f.Add("I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<")
	f.Fuzz(func(t *testing.T, s string) { _, _ = emrtd.ParseMRZ(s) })
}

func FuzzParseDG2(f *testing.F) {
	f.Add(buildDG2(syntheticJPEG(f), 0))
	f.Add(buildDG2(syntheticJ2K(), 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		faces, err := emrtd.ParseDG2(b)
		for _, face := range faces {
			if err == nil && face.Size != len(face.Data) {
				t.Fatal("a face's size is not its data's")
			}
		}
	})
}

func FuzzParseDG14(f *testing.F) {
	f.Add(buildDG14(f, ecKey(f), true))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = emrtd.ParseDG14(b) })
}

func FuzzParseCardAccess(f *testing.F) {
	f.Add(buildCardAccess(f, 13))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = emrtd.ParseCardAccess(b) })
}

func FuzzParseCOM(f *testing.F) {
	f.Add(buildCOM(0x61, 0x75, 0x6e, 0x6f))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = emrtd.ParseCOM(b) })
}

func FuzzParsePublicKeyInfo(f *testing.F) {
	f.Add(spkiOf(f, ecKey(f).Public()))
	f.Add(spkiOf(f, rsaKey(f, 2).Public()))
	f.Add(brainpoolSPKI(f))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := emrtd.ParsePublicKeyInfo(b)
		if err == nil && k.Key == nil && k.Unsupported == "" {
			t.Fatal("a key with no usable key says nothing about why")
		}
	})
}

func FuzzParseCertificate(f *testing.F) {
	p := newPassport(f)
	f.Add(p.csca.der)
	f.Add(p.ds.der)
	f.Add(handCertificate(f, pkixName("A"), pkixName("B"), brainpoolSPKI(f), true, nil))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = emrtd.ParseCertificate(b) })
}

func FuzzParseMasterList(f *testing.F) {
	p := newPassport(f)
	f.Add(buildMasterList(f, masterListSigner(f, p.csca), p.csca.der))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = emrtd.ParseMasterList(b) })
}

func FuzzExamine(f *testing.F) {
	p := newPassport(f)
	trust := p.trust(f)
	challenge, _ := emrtd.NewChallenge()
	f.Add(p.input.SOD, p.input.DataGroups[1], p.input.DataGroups[15], p.respondAA(f, challenge))
	valid := map[emrtd.Outcome]bool{passedO: true, failedO: true, notPresentO: true, unverifiableO: true}
	f.Fuzz(func(t *testing.T, sod, dg1, dg15, response []byte) {
		in := p.input
		in.SOD = sod
		in.DataGroups = map[int][]byte{1: dg1, 2: p.input.DataGroups[2], 14: p.input.DataGroups[14], 15: dg15}
		in.ActiveAuthentication = &emrtd.ActiveAuthenticationResponse{Challenge: challenge, Signature: response}
		r := emrtd.Examine(in, trust, emrtd.Options{Time: evaluation})
		for _, c := range r.Checks {
			if !valid[c.Outcome] {
				t.Fatalf("check %+v has an outcome outside the four", c)
			}
		}
	})
}
