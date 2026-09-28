package binary

import (
	"errors"
	"fmt"
)

// ErrorKind classifies parse failures so callers can distinguish a
// truncated file from a corrupt structure or an illegal field value.
type ErrorKind string

// Parse failure kinds.
const (
	KindUnsupportedFormat  ErrorKind = "unsupported_format"
	KindUnsupportedVariant ErrorKind = "unsupported_variant"
	KindTruncated          ErrorKind = "truncated"
	KindCorrupt            ErrorKind = "corrupt_structure"
	KindInvalidField       ErrorKind = "invalid_field"
	KindInternal           ErrorKind = "internal"
)

// Sentinel errors allow errors.Is(err, binary.ErrTruncated) style checks.
var (
	ErrUnsupportedFormat  = errors.New("unsupported or unrecognized binary format")
	ErrUnsupportedVariant = errors.New("unsupported variant of the binary format")
	ErrTruncated          = errors.New("binary is truncated")
	ErrCorrupt            = errors.New("binary structure is corrupt")
	ErrInvalidField       = errors.New("invalid binary field")
	ErrInternal           = errors.New("internal parser error")
)

// kindSentinel maps an ErrorKind to its sentinel error.
var kindSentinel = map[ErrorKind]error{
	KindUnsupportedFormat:  ErrUnsupportedFormat,
	KindUnsupportedVariant: ErrUnsupportedVariant,
	KindTruncated:          ErrTruncated,
	KindCorrupt:            ErrCorrupt,
	KindInvalidField:       ErrInvalidField,
	KindInternal:           ErrInternal,
}

// Error is a structured parse error.
type Error struct {
	Kind   ErrorKind
	Format Format
	Offset int64
	Field  string
	Msg    string
	Err    error
}

func (e *Error) Error() string {
	where := "offset " + fmt.Sprintf("%d", e.Offset)
	if e.Field != "" {
		where = "offset " + fmt.Sprintf("%d", e.Offset) + " field " + e.Field
	}
	msg := string(e.Kind)
	if e.Format != "" {
		msg += " [" + string(e.Format) + "]"
	}
	msg += " at " + where
	if e.Msg != "" {
		msg += ": " + e.Msg
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap exposes the kind sentinel so errors.Is works, plus any nested Err.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if s, ok := kindSentinel[e.Kind]; ok {
		out = append(out, s)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}
