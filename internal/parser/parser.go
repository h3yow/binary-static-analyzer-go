// Package parser turns different executable formats into a unified model.
//
// Every parser either returns a fully usable model or an error wrapping one of
// the sentinel errors in errors.go, so callers can distinguish truncation,
// corruption, unknown formats and unsupported variants.
package parser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
)

// Parser parses one executable format.
type Parser interface {
	// Name returns the format identifier, e.g. "elf".
	Name() string
	// Sniff reports whether data looks like this format. It must not panic
	// on short or arbitrary input.
	Sniff(data []byte) bool
	// Parse converts data into the unified model. The context is honored so
	// configured timeouts terminate parsing instead of hanging.
	Parse(ctx context.Context, data []byte, opts Options) (*model.Binary, error)
}

// Options limits resource usage during parsing.
type Options struct {
	// MaxBinarySize rejects inputs larger than this many bytes (<=0 = unlimited).
	MaxBinarySize int64
	// MaxSectionBytes caps the bytes captured per section (Raw is nil above it).
	MaxSectionBytes int
	// MaxSections caps the number of sections that will be processed.
	MaxSections int
}

// DefaultOptions returns conservative resource limits.
func DefaultOptions() Options {
	return Options{
		MaxBinarySize:   256 << 20, // 256 MiB
		MaxSectionBytes: 16 << 20,  // 16 MiB
		MaxSections:     1 << 16,   // 65536
	}
}

// registry holds the available format parsers. Order is the sniff priority.
var registry = []Parser{
	&elfParser{},
	&peParser{},
	&machoParser{},
}

// Register adds a parser to the front of the sniff priority list. It is
// intended for extensions/tests and is not safe for concurrent use with
// Parse calls.
func Register(p Parser) {
	registry = append([]Parser{p}, registry...)
}

// Parse sniffs the data and dispatches to the matching parser.
//
// Distinguishable outcomes (use errors.Is):
//
//   - ErrEmpty: no bytes at all
//   - ErrOversized: input exceeds opts.MaxBinarySize
//   - ErrUnknownFormat: no supported magic
//   - format-specific errors wrapping ErrTruncated / ErrCorrupt /
//     ErrUnsupported, with an offset and detail
func Parse(ctx context.Context, data []byte, opts Options) (*model.Binary, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, &ParseError{Cause: ErrEmpty, Offset: -1}
	}
	if opts.MaxBinarySize > 0 && int64(len(data)) > opts.MaxBinarySize {
		return nil, &ParseError{
			Cause:  ErrOversized,
			Detail: "input larger than configured maximum",
			Offset: int64(len(data)),
		}
	}
	for _, p := range registry {
		if !p.Sniff(data) {
			continue
		}
		b, err := p.Parse(ctx, data, opts)
		if err != nil {
			return nil, err
		}
		b.Size = int64(len(data))
		sum := sha256.Sum256(data)
		b.SourceSHA256 = hex.EncodeToString(sum[:])
		return b, nil
	}
	return nil, &ParseError{Cause: ErrUnknownFormat, Offset: 0}
}
