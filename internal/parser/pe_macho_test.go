package parser

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// buildMinimalPE constructs a legal PE32 with one .text section carrying
// marker bytes. Mutations in tests produce malformed variants.
func buildMinimalPE() []byte {
	const peOff = 0x80
	b := make([]byte, peOff+4)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], peOff)
	b[peOff], b[peOff+1], b[peOff+2], b[peOff+3] = 'P', 'E', 0, 0

	opt := make([]byte, 96)
	binary.LittleEndian.PutUint16(opt[0:], 0x10b) // PE32
	binary.LittleEndian.PutUint32(opt[16:], 0x1234)
	// COFF: machine=i386, nsec=1, ..., optSize=96, characteristics
	coffBytes := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffBytes[0:], 0x14c)
	binary.LittleEndian.PutUint16(coffBytes[2:], 1)
	binary.LittleEndian.PutUint16(coffBytes[16:], uint16(len(opt)))
	b = append(b, coffBytes...)
	b = append(b, opt...)

	// section header: .text, virtualSize=16, addr, rawSize=16, rawPtr=0x200
	sh := make([]byte, 40)
	copy(sh[0:8], ".text")
	binary.LittleEndian.PutUint32(sh[8:], 16)
	binary.LittleEndian.PutUint32(sh[12:], 0x1000)
	binary.LittleEndian.PutUint32(sh[16:], 16)
	binary.LittleEndian.PutUint32(sh[20:], 0x200)
	b = append(b, sh...)

	if len(b) < 0x200 {
		b = append(b, make([]byte, 0x200-len(b))...)
	}
	b = append(b, []byte("HELLO_PE_CONTENT")...)
	return b
}

func TestPE_MinimalValid(t *testing.T) {
	data := buildMinimalPE()
	logInput(t, "pe-valid", data)
	bin, err := Parse(context.Background(), data, DefaultOptions())
	if err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if bin.Format != "pe" || bin.Bits != 32 || len(bin.Sections) != 1 {
		t.Fatalf("bad model: %+v", bin)
	}
	t.Logf("verdict: %s %s sections=%d raw=%q",
		bin.FormatDetail, bin.Arch, len(bin.Sections), bin.Sections[0].Raw)
}

func TestPE_TruncatedMZ(t *testing.T) {
	data := []byte{'M', 'Z'}
	logInput(t, "pe-trunc-mz", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestPE_BadELfanew(t *testing.T) {
	data := buildMinimalPE()
	binary.LittleEndian.PutUint32(data[0x3c:], 0) // e_lfanew == 0
	logInput(t, "pe-zero-lfanew", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestPE_TruncatedSectionData(t *testing.T) {
	data := buildMinimalPE()
	// Cut the file before the raw data at 0x200.
	data = data[:0x150]
	logInput(t, "pe-section-trunc", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestPE_BadOptMagic(t *testing.T) {
	data := buildMinimalPE()
	// Optional header starts right after PE sig (4) + COFF (20) = 0x98.
	binary.LittleEndian.PutUint16(data[0x80+4+20:], 0xffff)
	logInput(t, "pe-bad-optmagic", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

// buildMinimalMachO64 builds a little-endian 64-bit thin Mach-O with one
// __TEXT,__text section and LC_MAIN.
func buildMinimalMachO64() []byte {
	fixed := func(s string, n int) []byte {
		out := make([]byte, n)
		copy(out, s)
		return out
	}

	// segment_command_64 (72) + one section_64 (80)
	sect := make([]byte, 0, 80)
	sect = append(sect, fixed("__text", 16)...)
	sect = append(sect, fixed("__TEXT", 16)...)
	tmp := make([]byte, 48)
	binary.LittleEndian.PutUint64(tmp[0:], 0x1000)  // addr
	binary.LittleEndian.PutUint64(tmp[8:], 5)       // size
	binary.LittleEndian.PutUint32(tmp[16:], 0x2000) // offset
	sect = append(sect, tmp...)

	segSize := uint32(72 + 80)
	var seg []byte
	seg = binary.LittleEndian.AppendUint32(seg, 0x19) // LC_SEGMENT_64
	seg = binary.LittleEndian.AppendUint32(seg, segSize)
	seg = append(seg, fixed("__TEXT", 16)...)
	tmp8 := make([]byte, 32)
	binary.LittleEndian.PutUint64(tmp8[0:], 0x100000000) // vmaddr
	binary.LittleEndian.PutUint64(tmp8[8:], 0x4000)      // vmsize
	binary.LittleEndian.PutUint64(tmp8[16:], 0)          // fileoff
	binary.LittleEndian.PutUint64(tmp8[24:], 0x4000)     // filesize
	seg = append(seg, tmp8...)
	prot := make([]byte, 16)
	binary.LittleEndian.PutUint32(prot[0:], 7) // maxprot
	binary.LittleEndian.PutUint32(prot[4:], 7) // initprot
	binary.LittleEndian.PutUint32(prot[8:], 1) // nsects
	// flags already zero
	seg = append(seg, prot...)
	seg = append(seg, sect...)

	var main []byte
	main = binary.LittleEndian.AppendUint32(main, 0x80000028)
	main = binary.LittleEndian.AppendUint32(main, 16)
	main = append(main, make([]byte, 8)...) // entryoff=0, stacksize=0

	cmds := append(seg, main...)
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(hdr[4:], 0x01000007)
	binary.LittleEndian.PutUint32(hdr[12:], 2) // filetype
	binary.LittleEndian.PutUint32(hdr[16:], 2) // ncmds
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(cmds)))
	out := append(hdr, cmds...)
	out = append(out, make([]byte, 0x2000-len(out))...)
	out = append(out, []byte("MACHO")...)
	return out
}

func TestMachO_MinimalValid(t *testing.T) {
	data := buildMinimalMachO64()
	logInput(t, "macho-valid", data)
	bin, err := Parse(context.Background(), data, DefaultOptions())
	if err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if len(bin.Sections) != 1 || bin.Sections[0].Name != "__TEXT,__text" {
		t.Fatalf("bad model: %+v", bin.Sections)
	}
	t.Logf("verdict: %s %s sec=%s", bin.FormatDetail, bin.Arch, bin.Sections[0].Name)
}

func TestMachO_FatUnsupported(t *testing.T) {
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:], 0xcafebabe) // fat magic
	logInput(t, "macho-fat", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestMachO_TruncatedHeader(t *testing.T) {
	data := []byte{0xce, 0xfa, 0xed, 0xfe, 0, 0, 0} // magic32LE + stub
	logInput(t, "macho-trunc", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}

func TestMachO_BadCmdsize(t *testing.T) {
	data := buildMinimalMachO64()
	// First load command cmdsize at hdr+4; set below 8.
	binary.LittleEndian.PutUint32(data[32+4:], 4)
	logInput(t, "macho-bad-cmdsize", data)
	_, err := Parse(context.Background(), data, DefaultOptions())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	t.Logf("verdict basis: %v", err)
}
