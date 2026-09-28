package parser

import (
	"context"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
)

// Thin Mach-O magic numbers (the high bit marks 64-bit; swapped = big endian).
const (
	magic32BE  = 0xfeedface
	magic64BE  = 0xfeedfacf
	magic32LE  = 0xcefaedfe
	magic64LE  = 0xcffaedfe
	magicFatBE = 0xcafebabe
	magicFatLE = 0xbebafeca
)

const (
	lcSegment     = 0x1
	lcSegment64   = 0x19
	lcMain        = 0x80000028
	mhHeader32Len = 28
	mhHeader64Len = 32
	segment32Len  = 56
	segment64Len  = 72
	section32Len  = 68
	section64Len  = 80
)

type machoParser struct{}

func (p *machoParser) Name() string { return string(model.FormatMachO) }

func (p *machoParser) Sniff(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m := readUint32(data, 0, true)
	switch m {
	case magic32BE, magic64BE, magic32LE, magic64LE, magicFatBE, magicFatLE:
		return true
	}
	return false
}

func (p *machoParser) Parse(ctx context.Context, data []byte, opts Options) (*model.Binary, error) {
	const format = "macho"

	if len(data) < 4 {
		return nil, trunc(format, "file shorter than Mach-O magic", int64(len(data)))
	}
	// Read magic both ways and classify endianness directly from the raw
	// bytes; assuming one byte order before classification would misread
	// ncmds/sizeofcmds for the opposite endianness.
	magicBE := readUint32(data, 0, false)
	switch magicBE {
	case magicFatBE, magicFatLE:
		return nil, unsupported(format, "fat/universal Mach-O archives are not supported")
	}

	var le bool
	var is64 bool
	switch magicBE {
	case magic64BE:
		le, is64 = false, true
	case magic32BE:
		le, is64 = false, false
	case magic64LE:
		le, is64 = true, true
	case magic32LE:
		le, is64 = true, false
	default:
		return nil, corrupt(format, "unrecognized Mach-O magic", 0)
	}

	hdrLen := mhHeader32Len
	if is64 {
		hdrLen = mhHeader64Len
	}
	if len(data) < hdrLen {
		return nil, trunc(format, "mach_header shorter than class requires", int64(len(data)))
	}
	cpuType := readUint32(data, 4, le)
	ncmds := int(readUint32(data, 16, le))
	sizeofcmds := int(readUint32(data, 20, le))
	cmdStart := hdrLen
	if cmdStart+sizeofcmds > len(data) {
		return nil, trunc(format, "load command region extends past end of file", int64(cmdStart))
	}
	if opts.MaxSections > 0 && ncmds > opts.MaxSections {
		return nil, &ParseError{Cause: ErrOversized, Format: format, Detail: "load command count exceeds configured limit", Offset: 16}
	}
	var entry uint64
	sections := make([]model.Section, 0)
	pos := cmdStart
	limit := cmdStart + sizeofcmds
	for i := 0; i < ncmds; i++ {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		if pos+8 > limit {
			return nil, trunc(format, "load command header extends past command region", int64(pos))
		}
		cmd := readUint32(data, pos, le)
		cmdsize := int(readUint32(data, pos+4, le))
		if cmdsize < 8 {
			return nil, corrupt(format, "load command cmdsize smaller than 8", int64(pos+4))
		}
		if pos+cmdsize > limit {
			return nil, trunc(format, "load command body extends past command region", int64(pos))
		}

		switch cmd {
		case lcMain:
			if cmdsize < 16 {
				return nil, corrupt(format, "LC_MAIN smaller than 16 bytes", int64(pos))
			}
			entry = readUint64(data, pos+8, le)
		case lcSegment, lcSegment64:
			segIs64 := cmd == lcSegment64
			segLen := segment32Len
			secLen := section32Len
			if segIs64 {
				segLen = segment64Len
				secLen = section64Len
			}
			if cmdsize < segLen {
				return nil, corrupt(format, "segment command smaller than class requires", int64(pos))
			}
			segName := cstring(data[pos+8:pos+24], 0)
			var nsects int
			var secDataOff int
			if segIs64 {
				nsects = int(readUint32(data, pos+64, le))
				secDataOff = pos + segment64Len
			} else {
				nsects = int(readUint32(data, pos+48, le))
				secDataOff = pos + segment32Len
			}
			if opts.MaxSections > 0 && len(sections)+nsects > opts.MaxSections {
				return nil, &ParseError{Cause: ErrOversized, Format: format, Detail: "section count exceeds configured limit", Offset: int64(pos)}
			}
			if nsects < 0 || secDataOff+nsects*secLen > pos+cmdsize {
				return nil, trunc(format, "section list in segment "+segName+" extends past command", int64(secDataOff))
			}
			for s := 0; s < nsects; s++ {
				so := secDataOff + s*secLen
				sectName := cstring(data[so:so+16], 0)
				segLabel := cstring(data[so+16:so+32], 0)
				var addr, size, off uint64
				var flags uint32
				if segIs64 {
					addr = readUint64(data, so+32, le)
					size = readUint64(data, so+40, le)
					off = uint64(readUint32(data, so+48, le))
					flags = readUint32(data, so+64, le)
				} else {
					addr = uint64(readUint32(data, so+32, le))
					size = uint64(readUint32(data, so+36, le))
					off = uint64(readUint32(data, so+44, le))
					flags = readUint32(data, so+56, le)
				}
				fullName := sectName
				if segLabel != "" {
					fullName = segLabel + "," + sectName
				}
				sec := model.Section{
					Name:    fullName,
					Address: addr,
					Offset:  off,
					Size:    size,
					Flags:   flags,
				}
				if size > 0 {
					if off > uint64(len(data)) || size > uint64(len(data))-off {
						sec.Truncated = true
						return nil, trunc(format, "section "+fullName+" data extends past end of file", int64(off))
					}
					raw := data[off : off+size]
					sec.Entropy = entropy(raw)
					if opts.MaxSectionBytes <= 0 || len(raw) <= opts.MaxSectionBytes {
						sec.Raw = raw
					}
				}
				sections = append(sections, sec)
			}
		}
		pos += cmdsize
	}

	bits := 32
	if is64 {
		bits = 64
	}
	return &model.Binary{
		Format:       model.FormatMachO,
		FormatDetail: machoDetail(is64, le),
		Arch:         machoArch(cpuType, is64),
		Bits:         bits,
		LittleEndian: le,
		EntryPoint:   entry,
		Sections:     sections,
	}, nil
}

func machoDetail(is64, le bool) string {
	d := "macho32"
	if is64 {
		d = "macho64"
	}
	if le {
		return d + "-little"
	}
	return d + "-big"
}

func machoArch(cpuType uint32, is64 bool) model.Architecture {
	// CPU_TYPE_X86=7, X86_64=0x01000007, ARM=12, ARM64=0x0100000c
	switch cpuType {
	case 7:
		return model.ArchX86
	case 0x01000007:
		return model.ArchX86_64
	case 12:
		return model.ArchARM
	case 0x0100000c:
		return model.ArchARM64
	default:
		return model.ArchUnknown
	}
}
