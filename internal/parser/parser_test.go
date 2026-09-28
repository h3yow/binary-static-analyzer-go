package parser

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// hexBytes decodes a hex literal for compact test input construction.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	return b
}

// logInput prints the exact input (length, head bytes) so failures are
// reproducible from the unit-test log alone.
func logInput(t *testing.T, label string, data []byte) {
	t.Helper()
	n := len(data)
	if n > 32 {
		n = 32
	}
	t.Logf("input[%s] len=%d head=% x", label, len(data), data[:n])
}

func TestParse_Empty(t *testing.T) {
	logInput(t, "empty", nil)
	_, err := Parse(context.Background(), nil, DefaultOptions())
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestParse_UnknownFormat(t *testing.T) {
	data := []byte("hello this is not an executable file")
	logInput(t, "unknown", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("want ErrUnknownFormat, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestParse_Oversized(t *testing.T) {
	data := make([]byte, 11)
	data[0], data[1], data[2], data[3] = 0x7f, 'E', 'L', 'F'
	logInput(t, "oversized", data)
	opts := DefaultOptions()
	opts.MaxBinarySize = 10
	_, err := Parse(context.Background(), data, opts)
	if !errors.Is(err, ErrOversized) {
		t.Fatalf("want ErrOversized, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestParse_RealELF(t *testing.T) {
	for _, path := range []string{"/bin/ls", "/bin/sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s unavailable: %v", path, err)
		}
		logInput(t, path, data)
		b, err := Parse(context.Background(), data, DefaultOptions())
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", path, err)
		}
		if b.Format != "elf" || len(b.Sections) == 0 || b.SourceSHA256 == "" {
			t.Fatalf("%s: bad model %+v", path, b)
		}
		t.Logf("verdict: format=%s arch=%s bits=%d sections=%d sha=%s",
			b.FormatDetail, b.Arch, b.Bits, len(b.Sections), b.SourceSHA256[:12])
	}
}

// --- ELF malformed / truncated cases -------------------------------------

// validELF64Header builds a minimal-but-legal ELF64 header with one
// SHT_NOBITS-free section so tests can mutate individual fields.
func validELF64() []byte {
	const hdrLen = 64
	const shLen = 64
	b := make([]byte, hdrLen+shLen)
	b[0], b[1], b[2], b[3] = 0x7f, 'E', 'L', 'F'
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // little endian
	b[6] = 1 // EV_CURRENT
	put16 := func(off int, v uint16) { b[off] = byte(v); b[off+1] = byte(v >> 8) }
	put32 := func(off int, v uint32) {
		for i := 0; i < 4; i++ {
			b[off+i] = byte(v >> (8 * i))
		}
	}
	put64 := func(off int, v uint64) {
		for i := 0; i < 8; i++ {
			b[off+i] = byte(v >> (8 * i))
		}
	}
	put16(16, 2)      // e_type ET_EXEC
	put16(18, 0x3e)   // e_machine X86_64
	put32(20, 1)      // e_version
	put64(24, 0x1000) // e_entry
	put64(40, hdrLen) // e_shoff right after header
	put16(52, hdrLen) // e_ehsize
	put16(54, 56)     // e_phentsize
	put16(58, shLen)  // e_shentsize
	put16(60, 1)      // e_shnum = 1 (only shdr0 null)
	put16(62, 0)      // e_shstrndx
	_ = put32
	return b
}

func TestELF_TruncatedIdent(t *testing.T) {
	// Full magic present but e_ident (16 bytes) incomplete: format known,
	// structure truncated.
	data := []byte{0x7f, 'E', 'L', 'F', 2, 1}
	logInput(t, "elf-trunc-ident", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestELF_BadClass(t *testing.T) {
	data := make([]byte, 64)
	copy(data[:4], elfMagic)
	data[4] = 9 // illegal EI_CLASS
	logInput(t, "elf-bad-class", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestELF_BadEndian(t *testing.T) {
	data := make([]byte, 64)
	copy(data[:4], elfMagic)
	data[4], data[5] = 2, 7 // class64, illegal EI_DATA
	logInput(t, "elf-bad-endian", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestELF_HeaderTruncated(t *testing.T) {
	// Valid class/endian but file ends before a 64-bit header.
	data := validELF64()[:20]
	logInput(t, "elf-header-trunc", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestELF_SectionTableTruncated(t *testing.T) {
	data := validELF64()
	// e_shoff (ELF64 offset 40) points past the file.
	for i := 0; i < 8; i++ {
		data[40+i] = 0xff
	}
	logInput(t, "elf-shoff-past-end", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestELF_BadShstrndx(t *testing.T) {
	data := validELF64()
	// 1 section but shstrndx claims index 5.
	put16le(data, 62, 5)
	logInput(t, "elf-bad-shstrndx", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestELF_MinimalValid(t *testing.T) {
	data := validELF64()
	logInput(t, "elf-valid-min", data)
	b, err := Parse(context.Background(), data, DefaultOptions())
	if err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if b.Arch != "x86_64" || b.Bits != 64 {
		t.Fatalf("bad model: %+v", b)
	}
	t.Logf("verdict: %s %s sections=%d", b.FormatDetail, b.Arch, len(b.Sections))
}

func TestELF_SectionDataTruncated(t *testing.T) {
	// Build a PROGBITS section pointing at data beyond EOF.
	data := validELF64()
	// Change shnum to 2, append one real section header; shdr1 claims bytes.
	put16le(data, 60, 2)
	sh := make([]byte, 64)
	put32le(sh, 4, 1)    // SHT_PROGBITS
	put64le(sh, 24, 500) // sh_offset = 500, past EOF
	put64le(sh, 32, 10)  // sh_size = 10
	data = append(data, sh...)
	logInput(t, "elf-section-data-trunc", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}
