package parser

import "errors"

// Distinguishable failure causes for binary parsing.
var (
	// ErrEmpty means the input contained no bytes at all.
	ErrEmpty = errors.New("parser: empty input")
	// ErrUnknownFormat means no supported magic number was recognized.
	ErrUnknownFormat = errors.New("parser: unknown or unsupported format")
	// ErrTruncated means a declared structure extends past the end of the input.
	ErrTruncated = errors.New("parser: truncated structure")
	// ErrCorrupt means an otherwise present structure holds an illegal value.
	ErrCorrupt = errors.New("parser: corrupt or illegal field")
	// ErrUnsupported means the format was recognized but this variant is not supported.
	ErrUnsupported = errors.New("parser: unsupported format variant")
	// ErrOversized means a declared size exceeds configured resource limits.
	ErrOversized = errors.New("parser: declared structure exceeds size limit")
)

// ParseError attaches context to one of the sentinel errors above.
type ParseError struct {
	Cause  error  // one of the sentinel errors
	Format string // detected format if known, "" otherwise
	Detail string // human-readable detail
	Offset int64  // offset where the problem was detected, -1 if unknown
}

func (e *ParseError) Error() string {
	s := "parse error"
	if e.Format != "" {
		s += " [" + e.Format + "]"
	}
	if e.Offset >= 0 {
		s += " at offset " + itoa(e.Offset)
	}
	s += ": " + e.Cause.Error()
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

func (e *ParseError) Unwrap() error { return e.Cause }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
