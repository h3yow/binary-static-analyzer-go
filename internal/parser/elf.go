package parser

import (
	"context"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
)

// ELF magic: \x7fELF
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// e_ident indices.
const (
	eiClass = 4
	eiData  = 5
)

const (
	elfClass32 = 1
	elfClass64 = 2
	elfDataLE  = 1
	elfDataBE  = 2
)

// ELF section types.
const (
	shtNull   = 0
	shtNobits = 8
	shtStrtab = 3
)

// Extended section count/index sentinels.
const (
	shnXindex = 0xffff
)

type elfParser struct{}

func (p *elfParser) Name() string { return string(model.FormatELF) }

func (p *elfParser) Sniff(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}

// elfFields holds the layout-dependent values for 32/64-bit ELF.
type elfFields struct {
	is64      bool
	le        bool
	bits      int
	entry     uint64
	shoff     uint64
	shentsize uint16
	shnum     uint16
	shstrndx  uint16
	machine   uint16
}

func (p *elfParser) Parse(ctx context.Context, data []byte, opts Options) (*model.Binary, error) {
	const format = "elf"

	// e_ident must be fully present to determine class/endianness.
	if len(data) < 16 {
		return nil, trunc(format, "e_ident incomplete; file shorter than 16 bytes", int64(len(data)))
	}
	class := data[eiClass]
	switch class {
	case elfClass32, elfClass64:
	default:
		return nil, corrupt(format, "invalid EI_CLASS (must be 1 or 2)", eiClass)
	}
	switch data[eiData] {
	case elfDataLE, elfDataBE:
	default:
		return nil, corrupt(format, "invalid EI_DATA (must be 1 little-endian or 2 big-endian)", eiData)
	}
	le := data[eiData] == elfDataLE // little-endian when EI_DATA == 1
	is64 := class == elfClass64

	hdrLen := 52
	shEntMin := 40
	if is64 {
		hdrLen = 64
		shEntMin = 64
	}
	if len(data) < hdrLen {
		return nil, trunc(format, "ELF header declared by class but file is shorter", int64(len(data)))
	}

	f := elfFields{is64: is64, le: le, bits: 32}
	if is64 {
		f.bits = 64
	}
	off := 16
	f.machine = readUint16(data, off+2, le)
	if is64 {
		// ELF64: e_entry@24, e_phoff@32, e_shoff@40; then e_flags@48,
		// e_ehsize@52, e_phentsize@54, e_phnum@56, e_shentsize@58,
		// e_shnum@60, e_shstrndx@62.
		f.entry = readUint64(data, 24, le)
		f.shoff = readUint64(data, 40, le)
		f.shentsize = readUint16(data, 58, le)
		f.shnum = readUint16(data, 60, le)
		f.shstrndx = readUint16(data, 62, le)
	} else {
		// ELF32: e_entry@24, e_phoff@28, e_shoff@32; then e_flags@36,
		// e_ehsize@40, e_phentsize@42, e_phnum@44, e_shentsize@46,
		// e_shnum@48, e_shstrndx@50.
		f.entry = uint64(readUint32(data, 24, le))
		f.shoff = uint64(readUint32(data, 32, le))
		f.shentsize = readUint16(data, 46, le)
		f.shnum = readUint16(data, 48, le)
		f.shstrndx = readUint16(data, 50, le)
	}

	ehsizeOff := 40
	if is64 {
		ehsizeOff = 52
	}
	ehsize := readUint16(data, ehsizeOff, le)
	if int(ehsize) < hdrLen {
		return nil, corrupt(format, "e_ehsize smaller than ELF header required by class", int64(ehsizeOff))
	}

	// Read a section header at a given index using the class-specific layout.
	readShdr := func(idx uint64) (name, typ uint32, flags, addr, secOff, secSize uint64, link uint32, err error) {
		base := f.shoff + idx*uint64(f.shentsize)
		if base > uint64(len(data)) || uint64(shEntMin) > uint64(len(data))-base {
			return 0, 0, 0, 0, 0, 0, 0, trunc(format, "section header extends past end of file", int64(base))
		}
		if is64 {
			name = readUint32(data, int(base)+0, le)
			typ = readUint32(data, int(base)+4, le)
			flags = readUint64(data, int(base)+8, le)
			addr = readUint64(data, int(base)+16, le)
			secOff = readUint64(data, int(base)+24, le)
			secSize = readUint64(data, int(base)+32, le)
			link = readUint32(data, int(base)+40, le)
		} else {
			name = readUint32(data, int(base)+0, le)
			typ = readUint32(data, int(base)+4, le)
			flags = uint64(readUint32(data, int(base)+8, le))
			addr = uint64(readUint32(data, int(base)+12, le))
			secOff = uint64(readUint32(data, int(base)+16, le))
			secSize = uint64(readUint32(data, int(base)+20, le))
			link = readUint32(data, int(base)+24, le)
		}
		return name, typ, flags, addr, secOff, secSize, link, nil
	}

	if int(f.shentsize) < shEntMin {
		return nil, corrupt(format, "e_shentsize smaller than section header required by class", int64(f.shoff))
	}

	shnum := uint64(f.shnum)
	shstrndx := uint64(f.shstrndx)

	// No section headers at all: valid stripped ELF, return header-only model.
	if f.shoff == 0 && shnum == 0 {
		return p.build(f, data, nil, nil, opts), nil
	}
	if f.shoff == 0 && shnum != 0 {
		return nil, corrupt(format, "e_shnum != 0 but e_shoff == 0", int64(f.shoff))
	}
	// shnum == 0 with sections present: real count lives in shdr0.sh_size.
	if shnum == 0 {
		_, _, _, _, _, realCount, _, err := readShdr(0)
		if err != nil {
			return nil, err
		}
		if realCount == 0 {
			return nil, corrupt(format, "shnum==0 but shdr0.sh_size is also zero", int64(f.shoff))
		}
		shnum = realCount
	}
	if opts.MaxSections > 0 && shnum > uint64(opts.MaxSections) {
		return nil, &ParseError{Cause: ErrOversized, Format: format, Detail: "section count exceeds configured limit", Offset: int64(f.shoff)}
	}
	// shstrndx == 0xffff: real index lives in shdr0.sh_link.
	if shstrndx == shnXindex {
		_, _, _, _, _, _, link, err := readShdr(0)
		if err != nil {
			return nil, err
		}
		shstrndx = uint64(link)
	}
	if shstrndx != 0 && shstrndx >= shnum {
		return nil, corrupt(format, "e_shstrndx points past last section", int64(f.shoff))
	}

	type shdr struct {
		nameOff uint32
		typ     uint32
		flags   uint64
		addr    uint64
		off     uint64
		size    uint64
	}
	headers := make([]shdr, 0, shnum)
	for i := uint64(0); i < shnum; i++ {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		name, typ, flags, addr, secOff, secSize, _, err := readShdr(i)
		if err != nil {
			return nil, err
		}
		headers = append(headers, shdr{name, typ, flags, addr, secOff, secSize})
	}

	// Resolve the section-name string table (.shstrtab).
	var strtab []byte
	if shstrndx != 0 {
		s := headers[shstrndx]
		if s.typ != shtStrtab {
			return nil, corrupt(format, "e_shstrndx does not point at a SHT_STRTAB section", int64(s.off))
		}
		if s.off > uint64(len(data)) || s.size > uint64(len(data))-uint64(s.off) {
			return nil, trunc(format, "section name string table extends past end of file", int64(s.off))
		}
		strtab = data[s.off : s.off+s.size]
	}

	sections := make([]model.Section, 0, len(headers))
	for i, h := range headers {
		if i == 0 && h.typ == shtNull {
			continue
		}
		name := ""
		if strtab != nil {
			if uint64(h.nameOff) >= uint64(len(strtab)) {
				return nil, corrupt(format, "section name offset outside .shstrtab", int64(f.shoff))
			}
			name = cstring(strtab, int(h.nameOff))
		}
		sec := model.Section{
			Name:    name,
			Address: h.addr,
			Offset:  h.off,
			Size:    h.size,
			Flags:   uint32(h.flags),
		}
		// SHT_NOBITS occupies no file space; everything else must fit.
		if h.typ != shtNobits && h.size > 0 {
			if h.off > uint64(len(data)) || h.size > uint64(len(data))-h.off {
				sec.Truncated = true
				return nil, trunc(format, "section data for "+orName(name, i)+" extends past end of file", int64(h.off))
			}
			raw := data[h.off : h.off+h.size]
			sec.Entropy = entropy(raw)
			if opts.MaxSectionBytes <= 0 || len(raw) <= opts.MaxSectionBytes {
				sec.Raw = raw
			}
		}
		sections = append(sections, sec)
	}

	return p.build(f, data, sections, nil, opts), nil
}

func (p *elfParser) build(f elfFields, data []byte, sections []model.Section, imports []model.Import, opts Options) *model.Binary {
	detail := "elf32"
	if f.is64 {
		detail = "elf64"
	}
	if f.le {
		detail += "-little"
	} else {
		detail += "-big"
	}
	return &model.Binary{
		Format:       model.FormatELF,
		FormatDetail: detail,
		Arch:         elfArch(f.machine),
		Bits:         f.bits,
		LittleEndian: f.le,
		EntryPoint:   f.entry,
		Sections:     sections,
		Imports:      imports,
	}
}

func elfArch(machine uint16) model.Architecture {
	switch machine {
	case 0x03:
		return model.ArchX86
	case 0x3e:
		return model.ArchX86_64
	case 0x28:
		return model.ArchARM
	case 0xb7:
		return model.ArchARM64
	default:
		return model.ArchUnknown
	}
}

func orName(name string, idx int) string {
	if name != "" {
		return name
	}
	return "section#" + itoa(int64(idx))
}
