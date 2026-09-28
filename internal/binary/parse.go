package binary

import "encoding/binary"

// Parse recognizes the container format from the leading magic bytes and
// parses the blob into the unified model.
func Parse(data []byte) (*Binary, error) {
	if len(data) < 2 {
		return nil, &Error{
			Kind:   KindUnsupportedFormat,
			Offset: 0,
			Msg:    "input too small to contain a known magic number",
		}
	}
	switch {
	case len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
		return parseELF(data)
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		// MZ is a recognizable magic with only two bytes; let the PE parser
		// report truncation precisely rather than calling it unknown.
		return parsePE(data)
	case len(data) >= 4 && isMachOMagic(data):
		return parseMachO(data)
	default:
		return nil, &Error{Kind: KindUnsupportedFormat, Offset: 0,
			Msg: "input too small or unknown magic number: " + hex4(data)}
	}
}

// isMachOMagic detects thin and fat Mach-O containers in either endianness.
func isMachOMagic(data []byte) bool {
	be := binary.BigEndian.Uint32(data[:4])
	le := binary.LittleEndian.Uint32(data[:4])
	switch be {
	case mhMagic32BE, mhMagic64BE, fatMagicBE, fat64MagicBE:
		return true
	}
	switch le {
	case mhMagic32BE, mhMagic64BE, fatMagicBE, fat64MagicBE:
		return true
	}
	return false
}

func hex4(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 9)
	out = append(out, "0x"...)
	for i := 0; i < 4; i++ {
		if i < len(data) {
			out = append(out, digits[data[i]>>4], digits[data[i]&0xf])
		} else {
			out = append(out, '?', '?')
		}
	}
	return string(out)
}
