package emrtd

import (
	"errors"
	"fmt"
)

// The errors a parser returns, for errors.Is.
//
// A parser never panics on hostile input: every structure it does not accept
// is one of these, wrapped with what was wrong.
var (
	// ErrMalformed is input that is not the structure it claims to be: a
	// truncated TLV, an ASN.1 value that does not decode, a field outside its
	// range, trailing bytes.
	ErrMalformed = errors.New("emrtd: malformed input")
	// ErrTooLarge is input beyond the limits this package parses: a file,
	// a length, a count or a nesting deeper than any eMRTD writes.
	ErrTooLarge = errors.New("emrtd: input exceeds the parsing limits")
	// ErrUnsupported is a well-formed structure this package does not
	// interpret, such as an indefinite BER length or an encrypted biometric
	// data block.
	ErrUnsupported = errors.New("emrtd: unsupported structure")
)

// malformed wraps ErrMalformed with what was wrong.
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// tooLarge wraps ErrTooLarge with what was too large.
func tooLarge(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrTooLarge, fmt.Sprintf(format, args...))
}

// unsupported wraps ErrUnsupported with what is not interpreted.
func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}
