package binary

import (
	"errors"
	"fmt"
)

// Mach-O magic numbers (as stored on disk).
const (
	mhMagic32BE  = 0xfeedface
	mhMagic32LE  = 0xcefaedfe
	mhMagic64BE  = 0xfeedfacf
	mhMagic64LE  = 0xcffaedfe
	fatMagicBE   = 0xcafebabe
	fatMagicLE   = 0xbebafeca
	fat64MagicBE = 0xcafebabf
	fat64MagicLE = 0xbfbafecf
)

const (
	cpuTypeX86    = 7
	cpuTypeX86_64 = 0x01000007
	cpuTypeARM    = 12
	cpuTypeARM64  = 0x0100000c

	mhObject   = 1
	mhExecute  = 2
	mhCore     = 4
	mhDylib    = 6
	mhDylinker = 7
	mhBundle   = 8

	lcSegment   = 0x01
	lcSegment64 = 0x19

	protRead  = 1
	protWrite = 2
	protExec  = 4

	sZerofill            = 1
	sGBZerofill          = 12
	sThreadLocalZerofill = 18
)

var machoCPU = map[uint32]Arch{
	cpuTypeX86:    ArchX86,
	cpuTypeX86_64: ArchAMD64,
	cpuTypeARM:    ArchARM,
	cpuTypeARM64:  ArchARM64,
}

func machoFileType(t uint32) FileType {
	switch t {
	case mhExecute:
		return TypeExecutable
	case mhDylib, mhDylinker, mhBundle:
		return TypeSharedLibrary
	case mhObject:
		return TypeObject
	case mhCore:
		return TypeCore
	default:
		return TypeUnknown
	}
}

func isMachOFatMagic(m uint32) bool {
	return m == fatMagicBE || m == fatMagicLE || m == fat64MagicBE || m == fat64MagicLE
}

func parseMachO(data []byte) (*Binary, error) {
	r := &reader{data: data}

	magic, err := r.u32(0, "mach_header.magic")
	if err != nil {
		return nil, markMachO(err)
	}
	if isMachOFatMagic(magic) {
		return nil, &Error{Kind: KindUnsupportedVariant, Format: FormatMachO,
			Field: "magic", Msg: "fat/universal Mach-O containers are not supported; extract a thin member first"}
	}

	var bits int
	switch magic {
	case mhMagic32BE, mhMagic32LE:
		bits = 32
		r.ord = bigEndian
		if magic == mhMagic32LE {
			r.ord = littleEndian
		}
	case mhMagic64BE, mhMagic64LE:
		bits = 64
		r.ord = bigEndian
		if magic == mhMagic64LE {
			r.ord = littleEndian
		}
	default:
		return nil, &Error{Kind: KindInvalidField, Format: FormatMachO, Offset: 0,
			Field: "magic", Msg: fmt.Sprintf("not a Mach-O magic: 0x%08x", magic)}
	}

	cpuType, err := r.u32(4, "cputype")
	if err != nil {
		return nil, markMachO(err)
	}
	arch, ok := machoCPU[cpuType]
	if !ok {
		return nil, &Error{Kind: KindUnsupportedVariant, Format: FormatMachO, Offset: 4,
			Field: "cputype", Msg: fmt.Sprintf("unsupported cputype 0x%x", cpuType)}
	}

	fileType, err := r.u32(12, "filetype")
	if err != nil {
		return nil, markMachO(err)
	}
	ncmds, err := r.u32(16, "ncmds")
	if err != nil {
		return nil, markMachO(err)
	}
	sizeofcmds, err := r.u32(20, "sizeofcmds")
	if err != nil {
		return nil, markMachO(err)
	}

	headerSize := int64(28)
	if bits == 64 {
		headerSize = 32
	}
	cmdEnd := headerSize + int64(sizeofcmds)
	if cmdEnd < headerSize || cmdEnd > int64(len(data)) {
		return nil, &Error{Kind: KindTruncated, Format: FormatMachO, Offset: cmdEnd,
			Field: "sizeofcmds",
			Msg: fmt.Sprintf("load command region [%d,%d) exceeds %d-byte file",
				headerSize, cmdEnd, len(data))}
	}

	sections := make([]Section, 0)
	off := headerSize
	for i := uint32(0); i < ncmds; i++ {
		if off+8 > cmdEnd {
			return nil, &Error{Kind: KindTruncated, Format: FormatMachO, Offset: off,
				Field: "load_command",
				Msg:   fmt.Sprintf("load command %d header does not fit within sizeofcmds", i)}
		}
		cmd, _ := r.u32(off, "lc.cmd")
		cmdsize, _ := r.u32(off+4, "lc.cmdsize")
		if cmdsize < 8 {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: off + 4,
				Field: "cmdsize", Msg: fmt.Sprintf("load command %d has cmdsize %d < 8", i, cmdsize)}
		}
		end := off + int64(cmdsize)
		if end > cmdEnd {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: off + 4,
				Field: "cmdsize",
				Msg:   fmt.Sprintf("load command %d (cmd=0x%x) overruns load command region", i, cmd)}
		}

		if (bits == 32 && cmd == lcSegment) || (bits == 64 && cmd == lcSegment64) {
			sects, err := parseMachOSegment(r, bits, off, end)
			if err != nil {
				return nil, err
			}
			sections = append(sections, sects...)
		}
		off = end
	}

	return &Binary{
		Format:     FormatMachO,
		Arch:       arch,
		Bits:       bits,
		BigEndian:  r.ord == bigEndian,
		Type:       machoFileType(fileType),
		EntryPoint: 0, // entry is carried by LC_UNIXTHREAD/LC_MAIN; not required here
		Sections:   sections,
		Size:       int64(len(data)),
	}, nil
}

func parseMachOSegment(r *reader, bits int, base, end int64) ([]Section, error) {
	var (
		nsects uint32
		err    error
	)
	if bits == 64 {
		// LC_SEGMENT_64 fixed prefix is 72 bytes; section_64 records 80 bytes.
		if base+72 > end {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: base + 4,
				Field: "cmdsize", Msg: "LC_SEGMENT_64 command smaller than 72 bytes"}
		}
		fileoff, _ := r.u64(base+40, "segment.fileoff")
		filesize, _ := r.u64(base+48, "segment.filesize")
		if fileoff+filesize < fileoff || fileoff+filesize > uint64(len(r.data)) {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO,
				Offset: int64(fileoff), Field: "segment.fileoff/filesize",
				Msg: fmt.Sprintf("segment file range [%d,%d) outside %d-byte file",
					fileoff, fileoff+filesize, len(r.data))}
		}
		nsects, err = r.u32(base+64, "segment.nsects")
		if err != nil {
			return nil, markMachO(err)
		}
		need := int64(nsects) * 80
		if need < 0 || base+72+need > end {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: base + 64,
				Field: "nsects", Msg: fmt.Sprintf("segment declares %d sections that do not fit in cmdsize", nsects)}
		}
	} else {
		// LC_SEGMENT fixed prefix is 56 bytes; section records 68 bytes.
		if base+56 > end {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: base + 4,
				Field: "cmdsize", Msg: "LC_SEGMENT command smaller than 56 bytes"}
		}
		fileoff32, _ := r.u32(base+32, "segment.fileoff")
		filesize32, _ := r.u32(base+36, "segment.filesize")
		if uint64(fileoff32)+uint64(filesize32) > uint64(len(r.data)) {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO,
				Offset: int64(fileoff32), Field: "segment.fileoff/filesize",
				Msg: fmt.Sprintf("segment file range [%d,%d) outside %d-byte file",
					fileoff32, uint64(fileoff32)+uint64(filesize32), len(r.data))}
		}
		nsects, err = r.u32(base+48, "segment.nsects")
		if err != nil {
			return nil, markMachO(err)
		}
		need := int64(nsects) * 68
		if need < 0 || base+56+need > end {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: base + 48,
				Field: "nsects", Msg: fmt.Sprintf("segment declares %d sections that do not fit in cmdsize", nsects)}
		}
	}

	initprotOff := base + 56
	recOff := base + 72
	recSize := int64(80)
	if bits == 32 {
		initprotOff = base + 40
		recOff = base + 56
		recSize = 68
	}
	initprot, err := r.u32(initprotOff, "segment.initprot")
	if err != nil {
		return nil, markMachO(err)
	}
	perm := machoPerm(initprot)

	out := make([]Section, 0, nsects)
	for i := uint32(0); i < nsects; i++ {
		sb := recOff + int64(i)*recSize
		// sectname[16] at +0
		name, err := fixedString(r.data[sb:sb+16], 16)
		if err != nil {
			return nil, &Error{Kind: KindCorrupt, Format: FormatMachO, Offset: sb,
				Field: "sectname", Msg: "section name is not NUL terminated within 16 bytes"}
		}
		var (
			addr    uint64
			size    uint64
			sOffset uint32
			sFlags  uint32
		)
		if bits == 64 {
			addr, _ = r.u64(sb+32, "section.addr")
			size, _ = r.u64(sb+40, "section.size")
			sOffset, _ = r.u32(sb+48, "section.offset")
			sFlags, _ = r.u32(sb+64, "section.flags")
		} else {
			a, _ := r.u32(sb+32, "section.addr")
			addr = uint64(a)
			sz, _ := r.u32(sb+36, "section.size")
			size = uint64(sz)
			sOffset, _ = r.u32(sb+40, "section.offset")
			sFlags, _ = r.u32(sb+56, "section.flags")
		}

		if !isMachoZerofill(sFlags) && sOffset != 0 {
			end2 := uint64(sOffset) + size
			if end2 < uint64(sOffset) || end2 > uint64(len(r.data)) {
				return nil, &Error{Kind: KindCorrupt, Format: FormatMachO,
					Offset: int64(sOffset), Field: "section.offset/size",
					Msg: fmt.Sprintf("section %q file range [%d,%d) outside %d-byte file",
						name, sOffset, end2, len(r.data))}
			}
		}
		out = append(out, Section{
			Name:     name,
			Address:  addr,
			Offset:   uint64(sOffset),
			Size:     size,
			Perm:     perm,
			RawFlags: sFlags,
			RawType:  0,
		})
	}
	return out, nil
}

func isMachoZerofill(flags uint32) bool {
	t := flags & 0xff
	return t == sZerofill || t == sGBZerofill || t == sThreadLocalZerofill
}

// fixedString reads a NUL-padded fixed-width string field.
func fixedString(b []byte, n int) (string, error) {
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return string(b[:i]), nil
		}
	}
	return "", fmt.Errorf("field is not NUL terminated")
}

func machoPerm(protections uint32) Perm {
	var p Perm
	if protections&protRead != 0 {
		p |= PermRead
	}
	if protections&protWrite != 0 {
		p |= PermWrite
	}
	if protections&protExec != 0 {
		p |= PermExecute
	}
	return p
}

func markMachO(err error) error {
	var pe *Error
	if errors.As(err, &pe) {
		if pe.Format == "" {
			pe.Format = FormatMachO
		}
		return pe
	}
	return err
}
