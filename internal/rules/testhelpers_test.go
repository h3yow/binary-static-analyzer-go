package rules

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildELF creates the same minimal ELF64 LE fixture used in binary tests
// (duplicated here to avoid exporting test helpers): .text + .data("SECRET")
// + .shstrtab.
func buildELF(t *testing.T) []byte {
	t.Helper()
	names := "\x00.text\x00.data\x00.shstrtab\x00"
	nameOff := func(s string) uint32 { return uint32(bytes.Index([]byte(names), []byte(s))) }

	textBody := []byte{0xcc, 0x90, 0x90}
	dataBody := []byte("SECRET")
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x7f, 'E', 'L', 'F'
	hdr[4], hdr[5], hdr[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(hdr[16:], 2)
	le.PutUint16(hdr[18:], 0x3e)
	le.PutUint32(hdr[20:], 1)
	le.PutUint64(hdr[24:], 0x400010)
	le.PutUint16(hdr[58:], 64)
	le.PutUint16(hdr[60:], 4)
	le.PutUint16(hdr[62:], 3)

	var buf bytes.Buffer
	buf.Write(hdr)
	textOff := uint64(buf.Len())
	buf.Write(textBody)
	dataOff := uint64(buf.Len())
	buf.Write(dataBody)
	strOff := uint64(buf.Len())
	buf.WriteString(names)
	shoff := uint64(buf.Len())
	buf.Write(make([]byte, 64)) // null
	writeShdr := func(name uint32, typ uint32, flags uint64, addr, off, size uint64) {
		sh := make([]byte, 64)
		le.PutUint32(sh[0:], name)
		le.PutUint32(sh[4:], typ)
		le.PutUint64(sh[8:], flags)
		le.PutUint64(sh[16:], addr)
		le.PutUint64(sh[24:], off)
		le.PutUint64(sh[32:], size)
		buf.Write(sh)
	}
	writeShdr(nameOff(".text"), 1, 2|4, 0x401000, textOff, uint64(len(textBody)))
	writeShdr(nameOff(".data"), 1, 2, 0x402000, dataOff, uint64(len(dataBody)))
	writeShdr(nameOff(".shstrtab"), 3, 0, 0, strOff, uint64(len(names)))
	out := buf.Bytes()
	le.PutUint64(out[40:], shoff)
	return out
}

func binaryDataOffset(t *testing.T, raw []byte) int {
	t.Helper()
	// shoff + null(64) + .text shdr(64) -> .data sh_offset at +24
	shoff := int(binary.LittleEndian.Uint64(raw[40:]))
	return int(binary.LittleEndian.Uint64(raw[shoff+64+64+24:]))
}
