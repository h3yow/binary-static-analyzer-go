package binary

import "fmt"

// order selects multi-byte byte order.
type order bool

const (
	littleEndian order = false
	bigEndian    order = true
)

// reader is a bounds-checked byte cursor. Every accessor returns
// ErrTruncated instead of panicking when the blob is too short.
type reader struct {
	data []byte
	ord  order
}

// bounds returns a truncated error if [off,off+n) is outside the blob.
func (r *reader) bounds(off int64, n int64, field string) error {
	if off < 0 || n < 0 || off > int64(len(r.data)) || off+n > int64(len(r.data)) {
		return &Error{Kind: KindTruncated, Offset: off, Field: field,
			Msg: fmt.Sprintf("need %d bytes, blob size is %d", n, len(r.data))}
	}
	return nil
}

func (r *reader) u8(off int64, field string) (byte, error) {
	if err := r.bounds(off, 1, field); err != nil {
		return 0, err
	}
	return r.data[off], nil
}

func (r *reader) u16(off int64, field string) (uint16, error) {
	if err := r.bounds(off, 2, field); err != nil {
		return 0, err
	}
	a, b := r.data[off], r.data[off+1]
	if r.ord == littleEndian {
		return uint16(a) | uint16(b)<<8, nil
	}
	return uint16(a)<<8 | uint16(b), nil
}

func (r *reader) u32(off int64, field string) (uint32, error) {
	if err := r.bounds(off, 4, field); err != nil {
		return 0, err
	}
	a, b, c, d := r.data[off], r.data[off+1], r.data[off+2], r.data[off+3]
	if r.ord == littleEndian {
		return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24, nil
	}
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d), nil
}

func (r *reader) u64(off int64, field string) (uint64, error) {
	if err := r.bounds(off, 8, field); err != nil {
		return 0, err
	}
	var v uint64
	for i := int64(0); i < 8; i++ {
		b := r.data[off+i]
		if r.ord == littleEndian {
			v |= uint64(b) << (8 * i)
		} else {
			v = v<<8 | uint64(b)
		}
	}
	return v, nil
}

// bytes returns a sub-slice after a bounds check. The returned slice shares
// backing storage with the input blob.
func (r *reader) bytes(off int64, n int64, field string) ([]byte, error) {
	if err := r.bounds(off, n, field); err != nil {
		return nil, err
	}
	return r.data[off : off+n], nil
}
