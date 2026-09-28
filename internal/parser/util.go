package parser

import (
	"context"
	"encoding/binary"
	"math"
)

// readUint16/32/64 decode integers without panicking on short buffers.
// Callers must have bounds-checked off already; these helpers return 0 if
// the read would run past the slice.
func readUint16(b []byte, off int, le bool) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	if le {
		return binary.LittleEndian.Uint16(b[off:])
	}
	return binary.BigEndian.Uint16(b[off:])
}

func readUint32(b []byte, off int, le bool) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	if le {
		return binary.LittleEndian.Uint32(b[off:])
	}
	return binary.BigEndian.Uint32(b[off:])
}

func readUint64(b []byte, off int, le bool) uint64 {
	if off < 0 || off+8 > len(b) {
		return 0
	}
	if le {
		return binary.LittleEndian.Uint64(b[off:])
	}
	return binary.BigEndian.Uint64(b[off:])
}

// sliceAt returns b[off:off+n] with full bounds checking. The bool is false
// (rather than panicking) when the requested window exceeds the input.
func sliceAt(b []byte, off, n uint64) ([]byte, bool) {
	if off > uint64(len(b)) || n > uint64(len(b))-off {
		return nil, false
	}
	return b[off : off+n], true
}

// cstring extracts a NUL-terminated string from b starting at off.
func cstring(b []byte, off int) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	return string(b[off:end])
}

// entropy computes Shannon entropy (bits per byte, 0..8) of data.
func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, v := range data {
		counts[v]++
	}
	var h float64
	n := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func trunc(format, detail string, offset int64) *ParseError {
	return &ParseError{Cause: ErrTruncated, Format: format, Detail: detail, Offset: offset}
}

func corrupt(format, detail string, offset int64) *ParseError {
	return &ParseError{Cause: ErrCorrupt, Format: format, Detail: detail, Offset: offset}
}

func unsupported(format, detail string) *ParseError {
	return &ParseError{Cause: ErrUnsupported, Format: format, Detail: detail, Offset: -1}
}

// checkContext returns ctx.Err() if the context is already done.
func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
