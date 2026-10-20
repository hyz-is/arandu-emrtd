package emrtd

import (
	"fmt"
	"strings"
)

// MRZFormat is the layout of a machine readable zone (ICAO Doc 9303 Parts 4
// to 6).
type MRZFormat string

// The three layouts.
const (
	// MRZTD1 is three lines of 30 characters: identity cards, the Brazilian
	// CIN among them.
	MRZTD1 MRZFormat = "td1"
	// MRZTD2 is two lines of 36 characters.
	MRZTD2 MRZFormat = "td2"
	// MRZTD3 is two lines of 44 characters: passports.
	MRZTD3 MRZFormat = "td3"
)

// The names of the MRZ fields, as FieldComparison and DigitCheck name them.
const (
	FieldDocumentCode        = "document_code"
	FieldIssuingState        = "issuing_state"
	FieldPrimaryIdentifier   = "primary_identifier"
	FieldSecondaryIdentifier = "secondary_identifier"
	FieldDocumentNumber      = "document_number"
	FieldNationality         = "nationality"
	FieldDateOfBirth         = "date_of_birth"
	FieldSex                 = "sex"
	FieldDateOfExpiry        = "date_of_expiry"
	FieldOptionalData1       = "optional_data_1"
	FieldOptionalData2       = "optional_data_2"
	FieldComposite           = "composite"
)

// MRZ is a parsed machine readable zone, from DG1 or from the printed page.
//
// Every field is personal data. A Report carries it because the application
// needs it; the application keeps it as it keeps any document data, and the
// Details of a Report never repeat it.
type MRZ struct {
	Format MRZFormat `json:"format"`
	// Lines is the MRZ as written, one string per line.
	Lines []string `json:"lines"`
	// DocumentCode is "P<", "PP", "I<", "ID" and so on, filler included.
	DocumentCode string `json:"document_code"`
	// IssuingState is the three-letter code of the issuing state or
	// organization, "BRA" for Brazil.
	IssuingState string `json:"issuing_state"`
	// PrimaryIdentifier and SecondaryIdentifier are the name, with the filler
	// read as spaces.
	PrimaryIdentifier   string `json:"primary_identifier"`
	SecondaryIdentifier string `json:"secondary_identifier"`
	// DocumentNumber is the document number without filler, the long form of
	// a TD1 number included.
	DocumentNumber string `json:"document_number"`
	Nationality    string `json:"nationality"`
	// DateOfBirth and DateOfExpiry are YYMMDD as written; the century is not
	// in the MRZ, and a filler in a date is kept.
	DateOfBirth  string `json:"date_of_birth"`
	Sex          string `json:"sex"`
	DateOfExpiry string `json:"date_of_expiry"`
	// OptionalData1 is the optional data of line 2 for TD2 and TD3 (the
	// personal number of a passport), of line 1 for TD1; OptionalData2 is the
	// optional data of line 2 of a TD1. Filler is kept.
	OptionalData1 string `json:"optional_data_1"`
	OptionalData2 string `json:"optional_data_2,omitempty"`
	// CheckDigits is every check digit of the layout, with its outcome.
	CheckDigits []DigitCheck `json:"check_digits"`
}

// DigitCheck is one check digit of an MRZ.
type DigitCheck struct {
	Field string `json:"field"`
	// Written is the digit as written; Computed is what the field computes
	// to.
	Written  string  `json:"written"`
	Computed string  `json:"computed"`
	Outcome  Outcome `json:"outcome"`
}

// ParseDG1 parses DG1 and the MRZ it holds.
func ParseDG1(b []byte) (*MRZ, error) {
	file, err := readFile(b, tagDG1)
	if err != nil {
		return nil, err
	}
	objects, err := children(file.value)
	if err != nil {
		return nil, err
	}
	data, ok := first(objects, 0x5f1f)
	if !ok {
		return nil, malformed("DG1 without the MRZ data object 5F1F")
	}
	var lines []string
	s := string(data.value)
	switch len(s) {
	case 90:
		lines = []string{s[:30], s[30:60], s[60:]}
	case 72:
		lines = []string{s[:36], s[36:]}
	case 88:
		lines = []string{s[:44], s[44:]}
	default:
		return nil, malformed("MRZ of %d characters", len(s))
	}
	return parseLines(lines)
}

// ParseMRZ parses an MRZ as text, as read from the printed page: lines
// separated by line breaks, with spaces and surrounding blanks ignored and
// letters folded to upper case. The characters must already be the MRZ's own
// (A to Z, 0 to 9 and the filler '<'); this function corrects no OCR error.
func ParseMRZ(text string) (*MRZ, error) {
	if len(text) > 1024 {
		return nil, tooLarge("MRZ text of %d bytes", len(text))
	}
	var lines []string
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r", "\n"), "\n") {
		line = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(line), " ", ""))
		if line != "" {
			lines = append(lines, line)
		}
	}
	return parseLines(lines)
}

func parseLines(lines []string) (*MRZ, error) {
	for _, line := range lines {
		for i := 0; i < len(line); i++ {
			if c := line[i]; !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '<') {
				return nil, malformed("MRZ character %q", c)
			}
		}
	}
	switch {
	case len(lines) == 3 && len(lines[0]) == 30 && len(lines[1]) == 30 && len(lines[2]) == 30:
		return parseTD1(lines), nil
	case len(lines) == 2 && len(lines[0]) == 36 && len(lines[1]) == 36:
		return parseTD23(MRZTD2, lines), nil
	case len(lines) == 2 && len(lines[0]) == 44 && len(lines[1]) == 44:
		return parseTD23(MRZTD3, lines), nil
	}
	return nil, malformed("MRZ of %d lines is none of TD1, TD2 or TD3", len(lines))
}

func parseTD1(l []string) *MRZ {
	m := &MRZ{
		Format:        MRZTD1,
		Lines:         l,
		DocumentCode:  l[0][0:2],
		IssuingState:  l[0][2:5],
		DateOfBirth:   l[1][0:6],
		Sex:           l[1][7:8],
		DateOfExpiry:  l[1][8:14],
		Nationality:   l[1][15:18],
		OptionalData1: l[0][15:30],
		OptionalData2: l[1][18:29],
	}
	m.PrimaryIdentifier, m.SecondaryIdentifier = names(l[2])
	number, digit := l[0][5:14], l[0][14:15]
	// A number longer than nine characters continues in the optional data,
	// whose last character before the filler is then the check digit.
	if digit == "<" && strings.Trim(l[0][15:30], "<") != "" {
		rest := l[0][15:30]
		end := strings.IndexByte(rest, '<')
		if end < 0 {
			end = len(rest)
		}
		if end > 0 {
			number += rest[:end-1]
			digit = rest[end-1 : end]
		}
	}
	m.DocumentNumber = strings.TrimRight(number, "<")
	m.CheckDigits = []DigitCheck{
		digitCheck(FieldDocumentNumber, number, digit),
		digitCheck(FieldDateOfBirth, l[1][0:6], l[1][6:7]),
		digitCheck(FieldDateOfExpiry, l[1][8:14], l[1][14:15]),
		digitCheck(FieldComposite, l[0][5:30]+l[1][0:7]+l[1][8:15]+l[1][18:29], l[1][29:30]),
	}
	return m
}

func parseTD23(format MRZFormat, l []string) *MRZ {
	m := &MRZ{
		Format:         format,
		Lines:          l,
		DocumentCode:   l[0][0:2],
		IssuingState:   l[0][2:5],
		DocumentNumber: strings.TrimRight(l[1][0:9], "<"),
		Nationality:    l[1][10:13],
		DateOfBirth:    l[1][13:19],
		Sex:            l[1][20:21],
		DateOfExpiry:   l[1][21:27],
	}
	m.PrimaryIdentifier, m.SecondaryIdentifier = names(l[0][5:])
	m.CheckDigits = []DigitCheck{
		digitCheck(FieldDocumentNumber, l[1][0:9], l[1][9:10]),
		digitCheck(FieldDateOfBirth, l[1][13:19], l[1][19:20]),
		digitCheck(FieldDateOfExpiry, l[1][21:27], l[1][27:28]),
	}
	if format == MRZTD3 {
		m.OptionalData1 = l[1][28:42]
		personal := digitCheck(FieldOptionalData1, l[1][28:42], l[1][42:43])
		// An unused personal number may carry a filler as its check digit.
		if strings.Trim(l[1][28:42], "<") == "" && l[1][42] == '<' {
			personal.Outcome = OutcomePassed
		}
		m.CheckDigits = append(m.CheckDigits, personal,
			digitCheck(FieldComposite, l[1][0:10]+l[1][13:20]+l[1][21:43], l[1][43:44]))
	} else {
		m.OptionalData1 = l[1][28:35]
		m.CheckDigits = append(m.CheckDigits,
			digitCheck(FieldComposite, l[1][0:10]+l[1][13:20]+l[1][21:35], l[1][35:36]))
	}
	return m
}

// names splits the name field into the primary and secondary identifiers.
func names(field string) (string, string) {
	primary, secondary, _ := strings.Cut(field, "<<")
	clean := func(s string) string {
		return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '<' }), " ")
	}
	return clean(primary), clean(secondary)
}

func digitCheck(field, data, written string) DigitCheck {
	c := DigitCheck{Field: field, Written: written, Outcome: OutcomeFailed}
	computed, err := CheckDigit(data)
	if err != nil {
		return c
	}
	c.Computed = fmt.Sprint(computed)
	if c.Computed == written {
		c.Outcome = OutcomePassed
	}
	return c
}

// CheckDigit computes the ICAO Doc 9303 check digit of an MRZ field: weights
// 7, 3, 1 over the values 0 to 9 for digits, 10 to 35 for A to Z and 0 for the
// filler, modulo 10.
func CheckDigit(field string) (int, error) {
	weights := [3]int{7, 3, 1}
	sum := 0
	for i := 0; i < len(field); i++ {
		c := field[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
		case c == '<':
			v = 0
		default:
			return 0, malformed("MRZ character %q", c)
		}
		sum += v * weights[i%3]
	}
	return sum % 10, nil
}

// FieldComparison is one MRZ field compared between the chip and the printed
// page. The values themselves are not repeated: they are in the two MRZs.
type FieldComparison struct {
	Field   string  `json:"field"`
	Outcome Outcome `json:"outcome"`
}

// CompareMRZ compares the DG1 MRZ with the MRZ of the printed page, field by
// field. A field differs when its characters differ; reading the printed page
// is the caller's, and a misread character is reported as a difference like
// any other.
func CompareMRZ(chip, printed *MRZ) []FieldComparison {
	if chip == nil || printed == nil {
		return nil
	}
	pairs := []struct {
		field string
		a, b  string
	}{
		{"format", string(chip.Format), string(printed.Format)},
		{FieldDocumentCode, chip.DocumentCode, printed.DocumentCode},
		{FieldIssuingState, chip.IssuingState, printed.IssuingState},
		{FieldPrimaryIdentifier, chip.PrimaryIdentifier, printed.PrimaryIdentifier},
		{FieldSecondaryIdentifier, chip.SecondaryIdentifier, printed.SecondaryIdentifier},
		{FieldDocumentNumber, chip.DocumentNumber, printed.DocumentNumber},
		{FieldNationality, chip.Nationality, printed.Nationality},
		{FieldDateOfBirth, chip.DateOfBirth, printed.DateOfBirth},
		{FieldSex, chip.Sex, printed.Sex},
		{FieldDateOfExpiry, chip.DateOfExpiry, printed.DateOfExpiry},
		{FieldOptionalData1, chip.OptionalData1, printed.OptionalData1},
		{FieldOptionalData2, chip.OptionalData2, printed.OptionalData2},
	}
	out := make([]FieldComparison, 0, len(pairs))
	for _, p := range pairs {
		o := OutcomePassed
		if p.a != p.b {
			o = OutcomeFailed
		}
		out = append(out, FieldComparison{Field: p.field, Outcome: o})
	}
	return out
}
