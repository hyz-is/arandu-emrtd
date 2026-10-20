package emrtd

import (
	"fmt"
	"slices"
)

// The tags of the LDS elementary files (ICAO Doc 9303 Part 10).
const (
	tagCOM = 0x60
	tagSOD = 0x77
	tagDG1 = 0x61
	tagDG2 = 0x75
	// tagDG14 and tagDG15 are the security data groups.
	tagDG14 = 0x6e
	tagDG15 = 0x6f
)

// dataGroupTags maps a data group number onto its tag.
var dataGroupTags = map[int]uint32{
	1: 0x61, 2: 0x75, 3: 0x63, 4: 0x76, 5: 0x65, 6: 0x66, 7: 0x67, 8: 0x68,
	9: 0x69, 10: 0x6a, 11: 0x6b, 12: 0x6c, 13: 0x6d, 14: 0x6e, 15: 0x6f, 16: 0x70,
}

// DataGroupTag is the tag the data group's file opens with, or 0 for a number
// outside 1 to 16.
func DataGroupTag(n int) uint32 { return dataGroupTags[n] }

// DataGroupNumber is the number of the data group a tag opens, or 0.
func DataGroupNumber(tag uint32) int {
	for n, t := range dataGroupTags {
		if t == tag {
			return n
		}
	}
	return 0
}

// FileName is the name a Report gives data group n: "DG1" to "DG16".
func FileName(n int) string { return fmt.Sprintf("DG%d", n) }

// The names a Report gives the files that are not data groups.
const (
	FileCOM        = "EF.COM"
	FileSOD        = "EF.SOD"
	FileCardAccess = "EF.CardAccess"
)

// COM is EF.COM: the LDS and Unicode versions and the data groups the chip
// says it holds. EF.COM is not signed; the SOD is what lists the data groups
// with authority.
type COM struct {
	// LDSVersion is the LDS version as "1.7" or "1.8".
	LDSVersion string `json:"lds_version,omitempty"`
	// UnicodeVersion is the Unicode version as "4.0.0".
	UnicodeVersion string `json:"unicode_version,omitempty"`
	// DataGroups is the data group numbers of the tag list, ascending.
	DataGroups []int `json:"data_groups"`
}

// ParseCOM parses EF.COM.
func ParseCOM(b []byte) (*COM, error) {
	file, err := readFile(b, tagCOM)
	if err != nil {
		return nil, err
	}
	objects, err := children(file.value)
	if err != nil {
		return nil, err
	}
	com := &COM{DataGroups: []int{}}
	if v, ok := first(objects, 0x5f01); ok {
		if len(v.value) != 4 || !digits(v.value) {
			return nil, malformed("LDS version %q", v.value)
		}
		com.LDSVersion = fmt.Sprintf("%d.%d", atoi(v.value[:2]), atoi(v.value[2:]))
	}
	if v, ok := first(objects, 0x5f36); ok {
		if len(v.value) != 6 || !digits(v.value) {
			return nil, malformed("Unicode version %q", v.value)
		}
		com.UnicodeVersion = fmt.Sprintf("%d.%d.%d", atoi(v.value[:2]), atoi(v.value[2:4]), atoi(v.value[4:]))
	}
	list, ok := first(objects, 0x5c)
	if !ok {
		return nil, malformed("EF.COM without a tag list")
	}
	for _, tag := range list.value {
		n := DataGroupNumber(uint32(tag))
		if n == 0 {
			return nil, malformed("tag list names %X, which is not a data group", tag)
		}
		if slices.Contains(com.DataGroups, n) {
			return nil, malformed("tag list names DG%d twice", n)
		}
		com.DataGroups = append(com.DataGroups, n)
	}
	slices.Sort(com.DataGroups)
	return com, nil
}

func digits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// atoi reads ASCII digits already checked by digits.
func atoi(b []byte) int {
	n := 0
	for _, c := range b {
		n = n*10 + int(c-'0')
	}
	return n
}
