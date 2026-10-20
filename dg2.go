package emrtd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// ImageFormat is the encoding of a face image.
type ImageFormat string

// The formats DG2 holds (ICAO Doc 9303 Part 10, ISO/IEC 19794-5).
const (
	// ImageJPEG is JPEG, which image/jpeg decodes.
	ImageJPEG ImageFormat = "jpeg"
	// ImageJPEG2000 is JPEG 2000, as a JP2 file or a bare codestream. The Go
	// standard library has no JPEG 2000 decoder, and this package does not
	// decode it: the bytes are returned as they are, for a decoder elsewhere.
	ImageJPEG2000 ImageFormat = "jpeg2000"
	// ImageUnknown is image data in neither format.
	ImageUnknown ImageFormat = "unknown"
)

// FaceImage is one face image of DG2.
//
// Data is biometric data: the application seals it as it seals a selfie, and
// a Report serialized to JSON leaves it out.
type FaceImage struct {
	// Format is what the image bytes are, by their signature.
	Format ImageFormat `json:"format"`
	// DeclaredType is the image data type the ISO/IEC 19794-5 record
	// declares (0 JPEG, 1 JPEG 2000), or -1 when no record was read.
	DeclaredType int `json:"declared_type"`
	// RecordVersion is the ISO/IEC 19794-5 version ("010", "030"), or empty.
	RecordVersion string `json:"record_version,omitempty"`
	// Width and Height are what the record declares, or 0.
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
	// Size is the length of Data in bytes.
	Size int `json:"size"`
	// SHA256 is the hex SHA-256 of Data.
	SHA256 string `json:"sha256"`
	// Data is the image bytes.
	Data []byte `json:"-"`
}

var (
	magicJPEG     = []byte{0xff, 0xd8, 0xff}
	magicJP2      = []byte{0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a}
	magicJ2K      = []byte{0xff, 0x4f, 0xff, 0x51}
	magicFaceType = []byte{'F', 'A', 'C', 0}
)

// ParseDG2 parses DG2 and returns its face images.
//
// The biometric data block of each instance is read as an ISO/IEC 19794-5
// facial record. A record of version 010, the one ICAO Doc 9303 profiles, is
// read field by field; for any other version the image is found by its
// signature in the block.
func ParseDG2(b []byte) ([]FaceImage, error) {
	file, err := readFile(b, tagDG2)
	if err != nil {
		return nil, err
	}
	top, err := children(file.value)
	if err != nil {
		return nil, err
	}
	group, ok := first(top, 0x7f61)
	if !ok {
		return nil, malformed("DG2 without a biometric information group template")
	}
	instances, err := children(group.value)
	if err != nil {
		return nil, err
	}
	var faces []FaceImage
	for _, bit := range instances {
		if bit.tag != 0x7f60 {
			continue
		}
		parts, err := children(bit.value)
		if err != nil {
			return nil, err
		}
		if _, ok := first(parts, 0x7f2e); ok {
			return nil, unsupported("enciphered biometric data block")
		}
		bdb, ok := first(parts, 0x5f2e)
		if !ok {
			return nil, malformed("biometric information template without a data block")
		}
		images, err := parseFaceRecord(bdb.value)
		if err != nil {
			return nil, err
		}
		faces = append(faces, images...)
		if len(faces) > maxFaces {
			return nil, tooLarge("more than %d face images", maxFaces)
		}
	}
	if len(faces) == 0 {
		return nil, malformed("DG2 holds no face image")
	}
	return faces, nil
}

func parseFaceRecord(bdb []byte) ([]FaceImage, error) {
	if len(bdb) < 14 || !bytes.Equal(bdb[:4], magicFaceType) {
		return scanImage(bdb, "")
	}
	version := string(bytes.TrimRight(bdb[4:8], "\x00"))
	if version != "010" {
		return scanImage(bdb, version)
	}
	count := int(binary.BigEndian.Uint16(bdb[12:14]))
	if count == 0 || count > maxFaces {
		return nil, malformed("facial record of %d images", count)
	}
	var out []FaceImage
	off := 14
	for range count {
		if off+20 > len(bdb) {
			return nil, malformed("truncated facial information")
		}
		blockLen := int(binary.BigEndian.Uint32(bdb[off : off+4]))
		points := int(binary.BigEndian.Uint16(bdb[off+4 : off+6]))
		info := off + 20 + 8*points
		if blockLen < 20+8*points+12 || blockLen > len(bdb)-off || info+12 > len(bdb) {
			return nil, malformed("facial record block of %d bytes", blockLen)
		}
		data := bdb[info+12 : off+blockLen]
		face := FaceImage{
			Format:        detectImage(data),
			DeclaredType:  int(bdb[info+1]),
			RecordVersion: version,
			Width:         int(binary.BigEndian.Uint16(bdb[info+2 : info+4])),
			Height:        int(binary.BigEndian.Uint16(bdb[info+4 : info+6])),
		}
		face.setData(data)
		out = append(out, face)
		off += blockLen
	}
	return out, nil
}

// scanImage finds the image in a block whose record layout is not read, by
// the first image signature in it.
func scanImage(bdb []byte, version string) ([]FaceImage, error) {
	start := -1
	for _, m := range [][]byte{magicJPEG, magicJP2, magicJ2K} {
		if i := bytes.Index(bdb, m); i >= 0 && (start < 0 || i < start) {
			start = i
		}
	}
	if start < 0 {
		return nil, malformed("no face image in the biometric data block")
	}
	face := FaceImage{Format: detectImage(bdb[start:]), DeclaredType: -1, RecordVersion: version}
	face.setData(bdb[start:])
	return []FaceImage{face}, nil
}

func (f *FaceImage) setData(data []byte) {
	f.Data = bytes.Clone(data)
	f.Size = len(data)
	sum := sha256.Sum256(data)
	f.SHA256 = hex.EncodeToString(sum[:])
}

// detectImage names the format of image bytes by their signature.
func detectImage(b []byte) ImageFormat {
	switch {
	case bytes.HasPrefix(b, magicJPEG):
		return ImageJPEG
	case bytes.HasPrefix(b, magicJP2), bytes.HasPrefix(b, magicJ2K):
		return ImageJPEG2000
	}
	return ImageUnknown
}
