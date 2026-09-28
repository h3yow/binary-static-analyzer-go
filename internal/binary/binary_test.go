package binary

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// buildELF64LE constructs a minimal valid little-endian ELF64 with two
// sections: .text (r-x) and .data (rw-) plus a .shstrtab.
func buildELF64LE(t *testing.T) []byte {
	t.Helper()

	names := "\x00.text\x00.data\x00.shstrtab\x00"
	nameOff := func(s string) uint32 { return uint32(bytes.Index([]byte(names), []byte(s))) }
	nameBytes := []byte(names)

	// File layout: header(64) | text body | data body | shstrtab | section headers
	textBody := []byte{0xcc, 0x90, 0x90}
	dataBody := []byte("SECRET")
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x7f, 'E', 'L', 'F'
	hdr[4] = elfClass64
	hdr[5] = elfDataLE
	hdr[6] = 1 // EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(hdr[16:], etExec)
	le.PutUint16(hdr[18:], 0x3e) // x86-64
	le.PutUint32(hdr[20:], 1)
	le.PutUint64(hdr[24:], 0x400010)
	// e_shoff filled later
	le.PutUint16(hdr[58:], 64) // shentsize
	le.PutUint16(hdr[60:], 4)  // shnum: null + 3
	le.PutUint16(hdr[62:], 3)  // shstrndx

	var buf bytes.Buffer
	buf.Write(hdr)
	textOff := uint64(buf.Len())
	buf.Write(textBody)
	dataOff := uint64(buf.Len())
	buf.Write(dataBody)
	strOff := uint64(buf.Len())
	buf.Write(nameBytes)
	shoff := uint64(buf.Len())

	// null section
	buf.Write(make([]byte, 64))

	writeShdr := func(name uint32, flags uint64, addr, off, size uint64) {
		sh := make([]byte, 64)
		binary.LittleEndian.PutUint32(sh[0:], name)
		binary.LittleEndian.PutUint32(sh[4:], 1) // PROGBITS for text/data
		binary.LittleEndian.PutUint64(sh[8:], flags)
		binary.LittleEndian.PutUint64(sh[16:], addr)
		binary.LittleEndian.PutUint64(sh[24:], off)
		binary.LittleEndian.PutUint64(sh[32:], size)
		buf.Write(sh)
	}
	writeShdr(nameOff(".text"), shfAlloc|shfExecinstr, 0x401000, textOff, uint64(len(textBody)))
	writeShdr(nameOff(".data"), shfAlloc|shfWrite, 0x402000, dataOff, uint64(len(dataBody)))
	// shstrtab section (type STRTAB=3, no alloc flags)
	sh := make([]byte, 64)
	binary.LittleEndian.PutUint32(sh[0:], nameOff(".shstrtab"))
	binary.LittleEndian.PutUint32(sh[4:], 3)
	binary.LittleEndian.PutUint64(sh[24:], strOff)
	binary.LittleEndian.PutUint64(sh[32:], uint64(len(nameBytes)))
	buf.Write(sh)

	out := buf.Bytes()
	binary.LittleEndian.PutUint64(out[40:], shoff)
	return out
}

func TestParseELF64HappyPath(t *testing.T) {
	in := buildELF64LE(t)
	t.Logf("input: %d-byte minimal ELF64 LE: % x", len(in), in[:min(64, len(in))])

	b, err := Parse(in)
	if err != nil {
		t.Fatalf("expected successful parse, got %v", err)
	}
	if b.Format != FormatELF || b.Arch != ArchAMD64 || b.Bits != 64 || b.Type != TypeExecutable {
		t.Fatalf("unexpected identity: %+v", b)
	}
	if b.EntryPoint != 0x400010 {
		t.Fatalf("entry = %#x", b.EntryPoint)
	}
	if len(b.Sections) != 3 {
		t.Fatalf("want 3 sections (null excluded), got %d: %+v", len(b.Sections), b.Sections)
	}
	want := map[string]Perm{".text": PermRead | PermExecute, ".data": PermRead | PermWrite, ".shstrtab": 0}
	for _, s := range b.Sections {
		wp, ok := want[s.Name]
		if !ok {
			t.Fatalf("unexpected section %q", s.Name)
		}
		if s.Perm != wp {
			t.Fatalf("section %q perm = %s (%d), want %s", s.Name, s.Perm, s.Perm, wp)
		}
		t.Logf("section %-10q perm=%s offset=%d size=%d (basis: sh_flags=0x%x)",
			s.Name, s.Perm, s.Offset, s.Size, s.RawFlags)
	}
}

func TestParseTruncatedAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		kind ErrorKind
		sent error
	}{
		{"empty", nil, KindUnsupportedFormat, ErrUnsupportedFormat},
		{"random bytes", []byte{1, 2, 3, 4, 5, 6, 7, 8}, KindUnsupportedFormat, ErrUnsupportedFormat},
		{"elf magic only", []byte{0x7f, 'E', 'L', 'F'}, KindTruncated, ErrTruncated},
		{"elf bad class", bytesWith(func(b []byte) {
			b[4] = 9
		}, buildELF64LE(t)[:16]), KindInvalidField, ErrInvalidField},
		{"elf truncated header", buildELF64LE(t)[:20], KindTruncated, ErrTruncated},
		{"elf truncated section table", truncateAt(buildELF64LE(t), 64+3+6), KindTruncated, ErrTruncated},
		{"elf section outside file", mutateELF(buildELF64LE(t), func(b []byte) {
			// Clobber .text sh_size (first section at shoff+64, size field +32).
			shoff := int(binary.LittleEndian.Uint64(b[40:]))
			binary.LittleEndian.PutUint64(b[shoff+64+32:], 0xffffffff)
		}), KindCorrupt, ErrCorrupt},
		{"elf bad shstrndx", mutateELF(buildELF64LE(t), func(b []byte) {
			binary.LittleEndian.PutUint16(b[62:], 99)
		}), KindCorrupt, ErrCorrupt},
		{"elf unsupported machine", mutateELF(buildELF64LE(t), func(b []byte) {
			binary.LittleEndian.PutUint16(b[18:], 0x9999)
		}), KindUnsupportedVariant, ErrUnsupportedVariant},
		{"mz only", []byte{'M', 'Z'}, KindTruncated, ErrTruncated},
		{"mz short", append([]byte{'M', 'Z'}, make([]byte, 60)...), KindTruncated, ErrTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input %q (%d bytes)", tc.name, len(tc.data))
			_, err := Parse(tc.data)
			if err == nil {
				t.Fatalf("expected error kind %s, got nil", tc.kind)
			}
			var pe *Error
			if !errors.As(err, &pe) {
				t.Fatalf("error %v is not *binary.Error", err)
			}
			t.Logf("decision basis: kind=%s field=%q offset=%d msg=%q", pe.Kind, pe.Field, pe.Offset, pe.Msg)
			if pe.Kind != tc.kind {
				t.Fatalf("kind = %s, want %s (err: %v)", pe.Kind, tc.kind, err)
			}
			if !errors.Is(err, tc.sent) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tc.sent)
			}
		})
	}
}

// buildPE64 constructs a minimal PE32+ with one section .code.
func buildPE64(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	dos := make([]byte, 64)
	dos[0], dos[1] = 'M', 'Z'
	peOff := uint32(64)
	binary.LittleEndian.PutUint32(dos[0x3c:], peOff)
	buf.Write(dos)

	buf.WriteString("PE\x00\x00")
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], peMachineAMD64)
	binary.LittleEndian.PutUint16(coff[2:], 1)    // 1 section
	binary.LittleEndian.PutUint16(coff[16:], 240) // optional header size
	binary.LittleEndian.PutUint16(coff[18:],
		peImageCharacteristicsExecutableImage)
	buf.Write(coff)

	opt := make([]byte, 240)
	binary.LittleEndian.PutUint16(opt[0:], pe32PlusMagic)
	binary.LittleEndian.PutUint32(opt[16:], 0x1024) // entry RVA
	buf.Write(opt)

	body := []byte{0xc3, 0x90, 0x90, 0x90}
	rawOff := uint32(buf.Len()) + 40
	sh := make([]byte, 40)
	copy(sh[0:], ".code")
	binary.LittleEndian.PutUint32(sh[12:], 0x1000)            // VA
	binary.LittleEndian.PutUint32(sh[16:], uint32(len(body))) // raw size
	binary.LittleEndian.PutUint32(sh[20:], rawOff)            // raw pointer
	binary.LittleEndian.PutUint32(sh[36:],
		peSectionMemRead|peSectionMemExecute|0x200000) // CNT_CODE
	buf.Write(sh)
	buf.Write(body)
	return buf.Bytes()
}

func TestParsePE64HappyPath(t *testing.T) {
	in := buildPE64(t)
	t.Logf("input: %d-byte minimal PE32+", len(in))
	b, err := Parse(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.Format != FormatPE || b.Arch != ArchAMD64 || b.Bits != 64 || b.Type != TypeExecutable {
		t.Fatalf("unexpected identity %+v", b)
	}
	if b.EntryPoint != 0x1024 {
		t.Fatalf("entry = %#x", b.EntryPoint)
	}
	if len(b.Sections) != 1 || b.Sections[0].Name != ".code" {
		t.Fatalf("sections = %+v", b.Sections)
	}
	if b.Sections[0].Perm != PermRead|PermExecute {
		t.Fatalf("perm = %s", b.Sections[0].Perm)
	}
	t.Logf("decision basis: section %q perm=%s raw_flags=0x%x",
		b.Sections[0].Name, b.Sections[0].Perm, b.Sections[0].RawFlags)
}

func TestParsePECorrupt(t *testing.T) {
	in := buildPE64(t)
	bad := make([]byte, len(in))
	copy(bad, in)
	// First section header starts right after DOS(64)+sig(4)+COFF(20)+opt(240).
	// Corrupt SizeOfRawData (offset 16 of the 40-byte header) to overrun EOF.
	shBase := 64 + 4 + 20 + 240
	binary.LittleEndian.PutUint32(bad[shBase+16:], 0x7fffffff)
	_, err := Parse(bad)
	var pe *Error
	if err == nil || !errors.As(err, &pe) || pe.Kind != KindCorrupt {
		t.Fatalf("want corrupt_structure, got %v", err)
	}
	t.Logf("input: PE with SizeOfRawData=0x7fffffff; basis: %v", err)
}

// buildMachO64LE constructs a minimal 64-bit little-endian Mach-O with one
// __text section inside a __TEXT segment.
func buildMachO64LE(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], mhMagic64LE)
	binary.LittleEndian.PutUint32(hdr[4:], cpuTypeX86_64)
	binary.LittleEndian.PutUint32(hdr[12:], mhExecute)
	binary.LittleEndian.PutUint32(hdr[16:], 1) // ncmds
	// sizeofcmds = 72 prefix + 80 section
	binary.LittleEndian.PutUint32(hdr[20:], 152)
	buf.Write(hdr)

	body := []byte{0xcc, 0xc3}
	fileoff := uint64(32 + 152)
	cmd := make([]byte, 72+80)
	binary.LittleEndian.PutUint32(cmd[0:], lcSegment64)
	binary.LittleEndian.PutUint32(cmd[4:], 152)
	copy(cmd[8:], "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint64(cmd[40:], fileoff)
	binary.LittleEndian.PutUint64(cmd[48:], uint64(len(body)))
	binary.LittleEndian.PutUint32(cmd[56:], protRead|protExec) // maxprot
	binary.LittleEndian.PutUint32(cmd[60:], protRead|protExec) // initprot
	binary.LittleEndian.PutUint32(cmd[64:], 1)                 // nsects

	// section_64 at cmd+72
	sb := cmd[72:]
	copy(sb[0:], "__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	copy(sb[16:], "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint64(sb[32:], 0x100000f70)
	binary.LittleEndian.PutUint64(sb[40:], uint64(len(body)))
	binary.LittleEndian.PutUint32(sb[48:], uint32(fileoff))
	binary.LittleEndian.PutUint32(sb[56:], 0)          // align
	binary.LittleEndian.PutUint32(sb[64:], 0x80000400) // S_ATTR_PURE_INSTRUCTIONS | SOME
	buf.Write(cmd)
	buf.Write(body)
	return buf.Bytes()
}

func TestParseMachOHappyPathAndFatRejection(t *testing.T) {
	in := buildMachO64LE(t)
	t.Logf("input: %d-byte minimal Mach-O 64 LE", len(in))
	b, err := Parse(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.Format != FormatMachO || b.Arch != ArchAMD64 || b.Bits != 64 || b.Type != TypeExecutable {
		t.Fatalf("identity %+v", b)
	}
	if len(b.Sections) != 1 || b.Sections[0].Name != "__text" {
		t.Fatalf("sections %+v", b.Sections)
	}
	if b.Sections[0].Perm != PermRead|PermExecute {
		t.Fatalf("perm = %s", b.Sections[0].Perm)
	}
	t.Logf("decision basis: section %q perm=%s flags=0x%x",
		b.Sections[0].Name, b.Sections[0].Perm, b.Sections[0].RawFlags)

	// Fat magic must be a distinguishable rejection, not a crash.
	fat := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1}
	_, err = Parse(fat)
	var pe *Error
	if err == nil || !errors.As(err, &pe) || pe.Kind != KindUnsupportedVariant {
		t.Fatalf("fat binary: want unsupported_variant, got %v", err)
	}
	t.Logf("fat input basis: %v", err)
}

func bytesWith(mut func([]byte), b []byte) []byte {
	mut(b)
	return b
}

func mutateELF(b []byte, mut func([]byte)) []byte {
	mut(b)
	return b
}

func truncateAt(b []byte, n int) []byte {
	if n > len(b) {
		n = len(b)
	}
	out := make([]byte, n)
	copy(out, b[:n])
	return out
}
