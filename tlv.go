package emrtd

// The limits every parser in this package holds. They are well above what an
// eMRTD writes and low enough that a hostile file cannot make a parser spend
// more than a bounded amount of memory or time.
const (
	// MaxFileSize is the largest elementary file accepted: EF.COM, EF.SOD,
	// EF.CardAccess or a data group. A passport's DG2 is typically 15 to
	// 100 KB.
	MaxFileSize = 1 << 20
	// MaxMasterListSize is the largest CSCA master list accepted.
	MaxMasterListSize = 16 << 20
	// MaxCRLSize is the largest certificate revocation list accepted.
	MaxCRLSize = 8 << 20
	// MaxMasterListCertificates is the most certificates read from one master
	// list.
	MaxMasterListCertificates = 20000

	maxTLVChildren   = 256
	maxTagBytes      = 3
	maxLengthBytes   = 3
	maxSecurityInfos = 64
	maxFaces         = 16
	maxCMSSigners    = 8
	maxCMSCerts      = 32
)

// tlv is one BER-TLV data object of ISO/IEC 7816-4, as the LDS files are
// written: a tag of up to three bytes, a definite length, a value.
type tlv struct {
	tag         uint32
	constructed bool
	value       []byte
	// full is the whole object, tag and length included.
	full []byte
}

// readTLV reads one data object from the front of b and returns it with the
// bytes after it.
//
// Only definite lengths are accepted: the LDS is written in DER-compatible
// BER, and an indefinite length in an eMRTD file is a file this package does
// not interpret.
func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, malformed("truncated data object")
	}
	first := b[0]
	tag := uint32(first)
	i := 1
	if first&0x1f == 0x1f {
		for {
			if i >= len(b) {
				return tlv{}, nil, malformed("truncated tag")
			}
			if i >= maxTagBytes {
				return tlv{}, nil, tooLarge("tag longer than %d bytes", maxTagBytes)
			}
			c := b[i]
			tag = tag<<8 | uint32(c)
			i++
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return tlv{}, nil, malformed("truncated length")
	}
	length := int(b[i])
	i++
	switch {
	case length == 0x80:
		return tlv{}, nil, unsupported("indefinite length")
	case length > 0x80:
		n := length & 0x7f
		if n > maxLengthBytes {
			return tlv{}, nil, tooLarge("length of %d bytes", n)
		}
		if i+n > len(b) {
			return tlv{}, nil, malformed("truncated length")
		}
		length = 0
		for j := range n {
			length = length<<8 | int(b[i+j])
		}
		i += n
	}
	if length > len(b)-i {
		return tlv{}, nil, malformed("value of %d bytes where %d remain", length, len(b)-i)
	}
	end := i + length
	return tlv{
		tag:         tag,
		constructed: first&0x20 != 0,
		value:       b[i:end:end],
		full:        b[:end:end],
	}, b[end:], nil
}

// children reads the data objects a constructed value holds.
func children(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		if len(out) >= maxTLVChildren {
			return nil, tooLarge("more than %d data objects", maxTLVChildren)
		}
		t, rest, err := readTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		b = rest
	}
	return out, nil
}

// first is the first child with the tag, or false.
func first(objects []tlv, tag uint32) (tlv, bool) {
	for _, o := range objects {
		if o.tag == tag {
			return o, true
		}
	}
	return tlv{}, false
}

// readFile reads an elementary file as one data object with the expected
// tag. Trailing 0x00 or 0xFF bytes, which a reader that reads whole blocks
// leaves after the object, are tolerated; anything else after it is not.
func readFile(b []byte, tag uint32) (tlv, error) {
	if len(b) > MaxFileSize {
		return tlv{}, tooLarge("file of %d bytes", len(b))
	}
	t, rest, err := readTLV(b)
	if err != nil {
		return tlv{}, err
	}
	if t.tag != tag {
		return tlv{}, malformed("tag %X where %X was expected", t.tag, tag)
	}
	if !padding(rest) {
		return tlv{}, malformed("%d bytes after the data object", len(rest))
	}
	return t, nil
}

// padding reports whether b is empty or only filler bytes.
func padding(b []byte) bool {
	for _, c := range b {
		if c != 0x00 && c != 0xff {
			return false
		}
	}
	return true
}

// fileSpan is the part of a provided file a data group hash covers: the data
// object itself, without the filler a block reader may have left after it.
// A file that does not parse is hashed whole.
func fileSpan(b []byte) []byte {
	if len(b) > MaxFileSize {
		return b
	}
	t, rest, err := readTLV(b)
	if err != nil || !padding(rest) {
		return b
	}
	return t.full
}
