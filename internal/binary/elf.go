package binary

import (
	"errors"
	"fmt"
)

const (
	elfClass32 = 1
	elfClass64 = 2

	elfDataLE = 1
	elfDataBE = 2

	// ELF identification field offsets.
	eiClass   = 4
	eiData    = 5
	eiVersion = 6

	// ELF file types (subset).
	etRel  = 1
	etExec = 2
	etDyn  = 3
	etCore = 4

	// Special section indexes.
	shnUndef  = 0
	shnXindex = 0xffff

	// ELF section flag bits.
	shfWrite     = 0x1
	shfAlloc     = 0x2
	shfExecinstr = 0x4
)

// elfMachine maps the ELF e_machine field to the neutral Arch model.
var elfMachine = map[uint16]Arch{
	0x03: ArchX86,
	0x3e: ArchAMD64,
	0x28: ArchARM,
	0xb7: ArchARM64,
}

func elfFileType(t uint16) FileType {
	switch t {
	case etExec:
		return TypeExecutable
	case etDyn:
		return TypeSharedLibrary
	case etRel:
		return TypeObject
	case etCore:
		return TypeCore
	default:
		return TypeUnknown
	}
}

func parseELF(data []byte) (*Binary, error) {
	r := &reader{data: data}

	class, err := r.u8(eiClass, "e_ident[EI_CLASS]")
	if err != nil {
		return nil, markELF(err)
	}
	var bits int
	switch class {
	case elfClass32:
		bits = 32
	case elfClass64:
		bits = 64
	default:
		return nil, &Error{Kind: KindInvalidField, Format: FormatELF, Offset: eiClass,
			Field: "e_ident[EI_CLASS]", Msg: fmt.Sprintf("unknown ELF class %d", class)}
	}

	dataEnc, err := r.u8(eiData, "e_ident[EI_DATA]")
	if err != nil {
		return nil, markELF(err)
	}
	switch dataEnc {
	case elfDataLE:
		r.ord = littleEndian
	case elfDataBE:
		r.ord = bigEndian
	default:
		return nil, &Error{Kind: KindInvalidField, Format: FormatELF, Offset: eiData,
			Field: "e_ident[EI_DATA]", Msg: fmt.Sprintf("unknown data encoding %d", dataEnc)}
	}

	identVer, err := r.u8(eiVersion, "e_ident[EI_VERSION]")
	if err != nil {
		return nil, markELF(err)
	}
	if identVer != 1 {
		return nil, &Error{Kind: KindInvalidField, Format: FormatELF, Offset: eiVersion,
			Field: "e_ident[EI_VERSION]", Msg: fmt.Sprintf("expected EV_CURRENT(1), got %d", identVer)}
	}

	var (
		eType     uint16
		machine   uint16
		version   uint32
		entry     uint64
		shoff     uint64
		shentsize uint16
		shnum     uint16
		shstrndx  uint16
	)

	if bits == 64 {
		// Elf64_Ehdr: fixed 64-byte layout.
		eType, _ = r.u16(16, "e_type")
		machine, err = r.u16(18, "e_machine")
		if err != nil {
			return nil, markELF(err)
		}
		version, err = r.u32(20, "e_version")
		if err != nil {
			return nil, markELF(err)
		}
		entry, err = r.u64(24, "e_entry")
		if err != nil {
			return nil, markELF(err)
		}
		shoff, err = r.u64(40, "e_shoff")
		if err != nil {
			return nil, markELF(err)
		}
		shentsize, err = r.u16(58, "e_shentsize")
		if err != nil {
			return nil, markELF(err)
		}
		shnum, err = r.u16(60, "e_shnum")
		if err != nil {
			return nil, markELF(err)
		}
		shstrndx, err = r.u16(62, "e_shstrndx")
		if err != nil {
			return nil, markELF(err)
		}
	} else {
		// Elf32_Ehdr: fixed 52-byte layout.
		eType, _ = r.u16(16, "e_type")
		machine, err = r.u16(18, "e_machine")
		if err != nil {
			return nil, markELF(err)
		}
		version, err = r.u32(20, "e_version")
		if err != nil {
			return nil, markELF(err)
		}
		entry32, err := r.u32(24, "e_entry")
		if err != nil {
			return nil, markELF(err)
		}
		entry = uint64(entry32)
		shoff32, err := r.u32(32, "e_shoff")
		if err != nil {
			return nil, markELF(err)
		}
		shoff = uint64(shoff32)
		shentsize, err = r.u16(46, "e_shentsize")
		if err != nil {
			return nil, markELF(err)
		}
		shnum, err = r.u16(48, "e_shnum")
		if err != nil {
			return nil, markELF(err)
		}
		shstrndx, err = r.u16(50, "e_shstrndx")
		if err != nil {
			return nil, markELF(err)
		}
	}

	if version != 1 {
		return nil, &Error{Kind: KindInvalidField, Format: FormatELF, Offset: 20,
			Field: "e_version", Msg: fmt.Sprintf("expected EV_CURRENT(1), got %d", version)}
	}
	arch, ok := elfMachine[machine]
	if !ok {
		return nil, &Error{Kind: KindUnsupportedVariant, Format: FormatELF, Offset: 18,
			Field: "e_machine", Msg: fmt.Sprintf("unsupported e_machine 0x%x", machine)}
	}

	// No section header table is legal for stripped binaries (e_shoff==0).
	var sections []Section
	if shoff != 0 {
		sections, err = parseELFSections(r, bits, shoff, shentsize, shnum, shstrndx)
		if err != nil {
			return nil, err
		}
	}

	return &Binary{
		Format:     FormatELF,
		Arch:       arch,
		Bits:       bits,
		BigEndian:  dataEnc == elfDataBE,
		Type:       elfFileType(eType),
		EntryPoint: entry,
		Sections:   sections,
		Size:       int64(len(data)),
	}, nil
}

// rawSh is the union of the fields we need from Elf{32,62}_Shdr.
type rawSh struct {
	nameOff uint32
	typ     uint32
	flags   uint64
	addr    uint64
	offset  uint64
	size    uint64
}

func parseELFSections(r *reader, bits int, shoff uint64, entsize, num, strndx uint16) ([]Section, error) {
	var expected uint16 = 64
	if bits == 32 {
		expected = 40
	}
	if entsize < expected {
		return nil, &Error{Kind: KindCorrupt, Format: FormatELF, Offset: int64(shoff),
			Field: "e_shentsize",
			Msg:   fmt.Sprintf("section header entry size %d smaller than %d", entsize, expected)}
	}
	if num == 0 {
		return nil, &Error{Kind: KindCorrupt, Format: FormatELF, Offset: int64(shoff),
			Field: "e_shnum", Msg: "section header table present but e_shnum is 0"}
	}
	if strndx == shnXindex {
		return nil, &Error{Kind: KindUnsupportedVariant, Format: FormatELF,
			Field: "e_shstrndx", Msg: "extended section numbering (SHN_XINDEX) is not supported"}
	}
	if int(strndx) >= int(num) {
		return nil, &Error{Kind: KindCorrupt, Format: FormatELF, Field: "e_shstrndx",
			Msg: fmt.Sprintf("section-name string table index %d is out of range (e_shnum=%d)", strndx, num)}
	}

	totalSize := int64(num) * int64(entsize)
	if totalSize <= 0 || shoff > uint64(^uint64(0)-uint64(totalSize)) {
		return nil, &Error{Kind: KindCorrupt, Format: FormatELF, Offset: int64(shoff),
			Field: "e_shoff", Msg: "section header table overflows address space"}
	}
	if err := r.bounds(int64(shoff), totalSize, "section header table"); err != nil {
		return nil, markELF(err)
	}

	raw := make([]rawSh, num)
	for i := uint16(0); i < num; i++ {
		base := int64(shoff) + int64(i)*int64(entsize)
		var s rawSh
		if bits == 64 {
			s.nameOff, _ = r.u32(base+0, "sh_name")
			s.typ, _ = r.u32(base+4, "sh_type")
			s.flags, _ = r.u64(base+8, "sh_flags")
			s.addr, _ = r.u64(base+16, "sh_addr")
			s.offset, _ = r.u64(base+24, "sh_offset")
			s.size, _ = r.u64(base+32, "sh_size")
		} else {
			s.nameOff, _ = r.u32(base+0, "sh_name")
			s.typ, _ = r.u32(base+4, "sh_type")
			f, _ := r.u32(base+8, "sh_flags")
			s.flags = uint64(f)
			a, _ := r.u32(base+12, "sh_addr")
			s.addr = uint64(a)
			o, _ := r.u32(base+16, "sh_offset")
			s.offset = uint64(o)
			sz, _ := r.u32(base+20, "sh_size")
			s.size = uint64(sz)
		}
		raw[i] = s
	}

	// Read the section-name string table.
	strtab := raw[strndx]
	if strtab.offset+strtab.size < strtab.offset {
		return nil, &Error{Kind: KindCorrupt, Format: FormatELF, Field: "sh_offset/sh_size",
			Msg: "section-name string table range overflows"}
	}
	names, err := r.bytes(int64(strtab.offset), int64(strtab.size), ".shstrtab")
	if err != nil {
		return nil, &Error{Kind: KindCorrupt, Format: FormatELF,
			Offset: int64(strtab.offset), Field: ".shstrtab",
			Msg: "section-name string table lies outside the file", Err: markELF(err)}
	}

	sections := make([]Section, 0, num)
	for i, s := range raw {
		if i == int(shnUndef) {
			continue // null section
		}
		if s.offset+s.size < s.offset || s.offset+s.size > uint64(len(r.data)) {
			return nil, &Error{Kind: KindCorrupt, Format: FormatELF,
				Offset: int64(s.offset), Field: "sh_offset/sh_size",
				Msg: fmt.Sprintf("section %d claims bytes [%d,%d) outside a %d-byte file",
					i, s.offset, s.offset+s.size, len(r.data))}
		}
		name, err := cstring(names, s.nameOff)
		if err != nil {
			return nil, &Error{Kind: KindCorrupt, Format: FormatELF,
				Offset: int64(strtab.offset) + int64(s.nameOff), Field: "sh_name",
				Msg: fmt.Sprintf("section %d name offset is outside .shstrtab", i), Err: err}
		}
		sections = append(sections, Section{
			Name:     name,
			Address:  s.addr,
			Offset:   s.offset,
			Size:     s.size,
			Perm:     elfPerm(s.flags),
			RawFlags: uint32(s.flags),
			RawType:  s.typ,
		})
	}
	return sections, nil
}

func elfPerm(flags uint64) Perm {
	var p Perm
	if flags&shfAlloc != 0 || flags&shfWrite != 0 || flags&shfExecinstr != 0 {
		p |= PermRead
	}
	if flags&shfWrite != 0 {
		p |= PermWrite
	}
	if flags&shfExecinstr != 0 {
		p |= PermExecute
	}
	return p
}

// cstring reads a NUL-terminated string from a string table.
func cstring(tab []byte, off uint32) (string, error) {
	if int(off) >= len(tab) {
		return "", fmt.Errorf("offset %d outside string table of size %d", off, len(tab))
	}
	for i := int(off); i < len(tab); i++ {
		if tab[i] == 0 {
			return string(tab[off:i]), nil
		}
	}
	return "", fmt.Errorf("string at offset %d is not NUL-terminated", off)
}

// markELF tags a parse Error as ELF when propagating reader errors.
func markELF(err error) error {
	var pe *Error
	if errors.As(err, &pe) {
		if pe.Format == "" {
			pe.Format = FormatELF
		}
		return pe
	}
	return err
}
