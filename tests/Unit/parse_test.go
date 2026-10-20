package unit_test

import (
	"errors"
	"strings"
	"testing"

	emrtd "github.com/hyz-is/arandu-emrtd"
)

// The specimen MRZs of ICAO Doc 9303 (Parts 4 and 5): an invented holder of
// the invented state Utopia, published as the known answer of every check
// digit. They are not anyone's document.
const (
	specimenTD3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"
	specimenTD1 = "I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<"
)

func TestCheckDigitsMatchTheICAOSpecimens(t *testing.T) {
	t.Parallel()
	for field, want := range map[string]int{"L898902C3": 6, "740812": 2, "120415": 9, "ZE184226B<<<<<": 1, "D23145890": 7} {
		got, err := emrtd.CheckDigit(field)
		if err != nil || got != want {
			t.Errorf("CheckDigit(%q) = %d, %v; want %d", field, got, err, want)
		}
	}
	if _, err := emrtd.CheckDigit("abc"); !errors.Is(err, emrtd.ErrMalformed) {
		t.Errorf("a lower-case field gave %v", err)
	}
}

func TestTheTD3SpecimenParsesWithEveryDigitRight(t *testing.T) {
	t.Parallel()
	m, err := emrtd.ParseMRZ(specimenTD3)
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != emrtd.MRZTD3 || m.DocumentCode != "P<" || m.IssuingState != "UTO" || m.DocumentNumber != "L898902C3" ||
		m.PrimaryIdentifier != "ERIKSSON" || m.SecondaryIdentifier != "ANNA MARIA" || m.DateOfBirth != "740812" ||
		m.Sex != "F" || m.DateOfExpiry != "120415" || m.OptionalData1 != "ZE184226B<<<<<" {
		t.Errorf("TD3 = %+v", m)
	}
	allPassed(t, m)
}

func TestTheTD1SpecimenParsesWithEveryDigitRight(t *testing.T) {
	t.Parallel()
	m, err := emrtd.ParseMRZ(specimenTD1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != emrtd.MRZTD1 || m.DocumentNumber != "D23145890" || m.Nationality != "UTO" || m.PrimaryIdentifier != "ERIKSSON" {
		t.Errorf("TD1 = %+v", m)
	}
	allPassed(t, m)
}

func TestALongTD1DocumentNumberContinuesInTheOptionalData(t *testing.T) {
	t.Parallel()
	// Number D23145890734 (twelve characters): nine in place, a filler for
	// the check digit, the rest and its digit in the optional data.
	number := "D23145890734"
	cd, _ := emrtd.CheckDigit(number)
	line1 := "I<UTO" + number[:9] + "<" + number[9:] + string(rune('0'+cd))
	line1 += strings.Repeat("<", 30-len(line1))
	line2 := "7408122F1204159UTO<<<<<<<<<<<"
	composite, _ := emrtd.CheckDigit(line1[5:30] + line2[0:7] + line2[8:15] + line2[18:29])
	line2 += string(rune('0' + composite))
	m, err := emrtd.ParseMRZ(line1 + "\n" + line2 + "\nERIKSSON<<ANNA<MARIA<<<<<<<<<<")
	if err != nil {
		t.Fatal(err)
	}
	if m.DocumentNumber != number {
		t.Errorf("document number = %q", m.DocumentNumber)
	}
	allPassed(t, m)
}

func TestAPrintedMRZIsReadWithBlanksAndLowerCase(t *testing.T) {
	t.Parallel()
	text := "  p<uto eriksson<<anna<maria<<<<<<<<<<<<<<<<<<< \r\n L898902C36UTO7408122F1204159ZE184226B<<<<<10\n\n"
	m, err := emrtd.ParseMRZ(text)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := emrtd.ParseMRZ(specimenTD3)
	for _, f := range emrtd.CompareMRZ(m, ref) {
		if f.Outcome != emrtd.OutcomePassed {
			t.Errorf("field %s differs", f.Field)
		}
	}
}

func TestAWrongCheckDigitIsReportedByField(t *testing.T) {
	t.Parallel()
	m, err := emrtd.ParseMRZ(strings.Replace(specimenTD3, "7408122", "7408123", 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range m.CheckDigits {
		bad := d.Field == emrtd.FieldDateOfBirth || d.Field == emrtd.FieldComposite
		if bad != (d.Outcome == emrtd.OutcomeFailed) {
			t.Errorf("digit %+v", d)
		}
	}
}

func TestMalformedMRZsAreRefused(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"", "P<UTO", specimenTD3 + "\nEXTRA", strings.Replace(specimenTD3, "<", "-", 1), strings.Repeat("A", 2000)} {
		if _, err := emrtd.ParseMRZ(text); err == nil {
			t.Errorf("ParseMRZ(%q) succeeded", text)
		}
	}
	if _, err := emrtd.ParseDG1([]byte{0x61, 0x03, 0x5f, 0x1f, 0x00}); !errors.Is(err, emrtd.ErrMalformed) {
		t.Errorf("an empty DG1 MRZ gave %v", err)
	}
}

func TestEFCOMListsItsDataGroups(t *testing.T) {
	t.Parallel()
	com := []byte{0x60, 0x16, 0x5f, 0x01, 0x04, '0', '1', '0', '8', 0x5f, 0x36, 0x06, '0', '4', '0', '0', '0', '0', 0x5c, 0x04, 0x6f, 0x61, 0x75, 0x6e}
	c, err := emrtd.ParseCOM(com)
	if err != nil {
		t.Fatal(err)
	}
	if c.LDSVersion != "1.8" || c.UnicodeVersion != "4.0.0" || len(c.DataGroups) != 4 || c.DataGroups[0] != 1 || c.DataGroups[3] != 15 {
		t.Errorf("EF.COM = %+v", c)
	}
	// Block-read filler after the object is tolerated; other bytes are not.
	if _, err := emrtd.ParseCOM(append(com, 0, 0, 0xff)); err != nil {
		t.Errorf("filler refused: %v", err)
	}
	if _, err := emrtd.ParseCOM(append(com, 1)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestTLVLimitsAreHeld(t *testing.T) {
	t.Parallel()
	for name, b := range map[string][]byte{
		"indefinite length": {0x60, 0x80, 0x00, 0x00},
		"truncated value":   {0x60, 0x05, 0x01},
		"four-byte length":  {0x60, 0x84, 0x00, 0x00, 0x00, 0x01, 0x00},
		"long tag":          {0x7f, 0xff, 0xff, 0x01, 0x00},
		"wrong tag":         {0x61, 0x00},
		"empty":             {},
	} {
		if _, err := emrtd.ParseCOM(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := emrtd.ParseCOM([]byte{0x60, 0x80, 0, 0}); !errors.Is(err, emrtd.ErrUnsupported) {
		t.Errorf("indefinite length gave %v, want ErrUnsupported", err)
	}
	if _, err := emrtd.ParseDG1(make([]byte, emrtd.MaxFileSize+1)); !errors.Is(err, emrtd.ErrTooLarge) {
		t.Errorf("an oversized file gave %v", err)
	}
}

func TestDataGroupTagsRoundTrip(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 16; n++ {
		if got := emrtd.DataGroupNumber(emrtd.DataGroupTag(n)); got != n {
			t.Errorf("DG%d round-trips to %d", n, got)
		}
	}
	if emrtd.DataGroupTag(17) != 0 || emrtd.DataGroupNumber(0x77) != 0 {
		t.Error("a number or tag outside the LDS was mapped")
	}
}

func TestPACEParameterIDsAreNamed(t *testing.T) {
	t.Parallel()
	// SET { SEQUENCE { id-PACE-ECDH-GM-AES-CBC-CMAC-128, 2, 13 } }
	der := []byte{0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0d}
	s, err := emrtd.ParseCardAccess(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.PACE) != 1 || s.PACE[0].Parameters != "brainpoolP256r1" || s.PACE[0].Cipher != "aes128" || s.PACE[0].KeyAgreement != "ecdh" || s.PACE[0].Mapping != "generic" {
		t.Errorf("PACE = %+v", s.PACE)
	}
}

func allPassed(t *testing.T, m *emrtd.MRZ) {
	t.Helper()
	if len(m.CheckDigits) == 0 {
		t.Fatal("no check digits")
	}
	for _, d := range m.CheckDigits {
		if d.Outcome != emrtd.OutcomePassed {
			t.Errorf("check digit %+v", d)
		}
	}
}
