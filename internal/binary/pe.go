package binary

import (
	"errors"
	"fmt"
)

const (
	pe32Magic     = 0x10b
	pe32PlusMagic = 0x20b

	peMachineI386  = 0x014c
	peMachineAMD64 = 0x8664
	peMachineARM   = 0x01c0
	peMachineARM64 = 0xaa64

	peImageCharacteristicsExecutableImage = 0x0002
	peImageCharacteristicsDLL             = 0x2000

	peSectionMemExecute = 0x20000000
	peSectionMemRead    = 0x40000000
	peSectionMemWrite   = 0x80000000
)

var peMachine = map[uint16]Arch{
	peMachineI386:  ArchX86,
	peMachineAMD64: ArchAMD64,
	peMachineARM:   ArchARM,
	peMachineARM64: ArchARM64,
}

func parsePE(data []byte) (*Binary, error) {
	r := &reader{data: data, ord: littleEndian}

	// PE is always little-endian; the DOS header needs at least 64 bytes to
	// contain e_lfanew at offset 0x3c.
	lfanew, err := r.u32(0x3c, "e_lfanew")
	if err != nil {
		return nil, &Error{Kind: KindTruncated, Format: FormatPE, Offset: 0x3c,
			Field: "e_lfanew", Msg: "DOS header too short to contain PE header pointer", Err: err}
	}
	peOff := int64(lfanew)
	if peOff+24 > int64(len(data)) || peOff < 0 {
		return nil, &Error{Kind: KindTruncated, Format: FormatPE, Offset: peOff,
			Msg: fmt.Sprintf("e_lfanew=%d does not leave room for PE signature and COFF header (file size %d)",
				lfanew, len(data))}
	}

	sig, err := r.bytes(peOff, 4, "PE signature")
	if err != nil {
		return nil, markPE(err)
	}
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return nil, &Error{Kind: KindInvalidField, Format: FormatPE, Offset: peOff,
			Field: "Signature", Msg: fmt.Sprintf("expected \"PE\\0\\0\", got % x", sig)}
	}

	coff := peOff + 4
	machine, err := r.u16(coff+0, "Machine")
	if err != nil {
		return nil, markPE(err)
	}
	if machine == 0 {
		return nil, &Error{Kind: KindInvalidField, Format: FormatPE, Offset: coff,
			Field: "Machine", Msg: "machine type is 0 (IMAGE_FILE_MACHINE_UNKNOWN image)"}
	}
	arch, ok := peMachine[machine]
	if !ok {
		return nil, &Error{Kind: KindUnsupportedVariant, Format: FormatPE, Offset: coff,
			Field: "Machine", Msg: fmt.Sprintf("unsupported machine 0x%x", machine)}
	}

	numSections, err := r.u16(coff+2, "NumberOfSections")
	if err != nil {
		return nil, markPE(err)
	}
	ptrSymTab, err := r.u32(coff+8, "PointerToSymbolTable")
	if err != nil {
		return nil, markPE(err)
	}
	numSymbols, err := r.u32(coff+12, "NumberOfSymbols")
	if err != nil {
		return nil, markPE(err)
	}
	optSize, err := r.u16(coff+16, "SizeOfOptionalHeader")
	if err != nil {
		return nil, markPE(err)
	}
	characteristics, err := r.u16(coff+18, "Characteristics")
	if err != nil {
		return nil, markPE(err)
	}

	optOff := coff + 20
	var (
		bits     int
		entryRVA uint32
		fileType FileType
	)
	switch {
	case characteristics&peImageCharacteristicsDLL != 0:
		fileType = TypeSharedLibrary
	case characteristics&peImageCharacteristicsExecutableImage != 0:
		fileType = TypeExecutable
	default:
		fileType = TypeObject
	}

	if optSize > 0 {
		optMagic, err := r.u16(optOff, "OptionalHeader.Magic")
		if err != nil {
			return nil, &Error{Kind: KindTruncated, Format: FormatPE, Offset: optOff,
				Field: "OptionalHeader", Msg: "optional header declared but not present", Err: err}
		}
		switch optMagic {
		case pe32Magic:
			bits = 32
		case pe32PlusMagic:
			bits = 64
		default:
			return nil, &Error{Kind: KindUnsupportedVariant, Format: FormatPE, Offset: optOff,
				Field: "OptionalHeader.Magic", Msg: fmt.Sprintf("unknown PE optional header magic 0x%x", optMagic)}
		}
		// AddressOfEntryPoint is at offset 16 in both PE32 and PE32+ layouts.
		entryRVA, err = r.u32(optOff+16, "AddressOfEntryPoint")
		if err != nil {
			return nil, markPE(err)
		}
	} else {
		// PE object (.obj) has no optional header; infer word size from machine.
		bits = archBits(arch)
	}
	if bits == 0 {
		bits = archBits(arch)
	}

	// Optional header itself must be fully present before the section table.
	if int64(optSize) < 0 || optOff+int64(optSize) > int64(len(data)) {
		return nil, &Error{Kind: KindTruncated, Format: FormatPE, Offset: optOff,
			Field: "SizeOfOptionalHeader",
			Msg:   fmt.Sprintf("optional header of %d bytes runs past end of %d-byte file", optSize, len(data))}
	}
	sectOff := optOff + int64(optSize)

	// COFF string table for long section names sits immediately after the
	// symbol table; symbol records are 18 bytes each.
	var strtab []byte
	if ptrSymTab != 0 {
		strStart := int64(ptrSymTab) + int64(numSymbols)*18
		if strStart < 0 || strStart+4 > int64(len(data)) {
			return nil, &Error{Kind: KindCorrupt, Format: FormatPE, Offset: strStart,
				Field: "COFF string table",
				Msg: fmt.Sprintf("symbol/string table pointer 0x%x (%d symbols) points outside file",
					ptrSymTab, numSymbols)}
		}
		strSize, _ := r.u32(strStart, "string table size")
		if int64(strStart)+int64(strSize) > int64(len(data)) {
			return nil, &Error{Kind: KindCorrupt, Format: FormatPE, Offset: strStart,
				Field: "COFF string table", Msg: "declared string table size runs past end of file"}
		}
		// First 4 bytes of the table are the size itself.
		strtab = data[strStart+4:]
	}

	sections, err := parsePESections(r, sectOff, numSections, strtab)
	if err != nil {
		return nil, err
	}

	return &Binary{
		Format:     FormatPE,
		Arch:       arch,
		Bits:       bits,
		BigEndian:  false,
		Type:       fileType,
		EntryPoint: uint64(entryRVA),
		Sections:   sections,
		Size:       int64(len(data)),
	}, nil
}

func parsePESections(r *reader, off int64, n uint16, strtab []byte) ([]Section, error) {
	if n == 0 {
		return nil, nil
	}
	total := int64(n) * 40
	if off < 0 || off+total < off || off+total > int64(len(r.data)) {
		return nil, &Error{Kind: KindTruncated, Format: FormatPE, Offset: off,
			Field: "section table",
			Msg:   fmt.Sprintf("section table for %d sections does not fit in %d-byte file", n, len(r.data))}
	}
	out := make([]Section, 0, n)
	for i := int64(0); i < int64(n); i++ {
		base := off + i*40
		name, err := peSectionName(r.data[base:base+8], strtab)
		if err != nil {
			return nil, &Error{Kind: KindCorrupt, Format: FormatPE, Offset: base,
				Field: "Name", Msg: fmt.Sprintf("section %d has invalid long name", i), Err: err}
		}
		vsize, _ := r.u32(base+8, "VirtualSize")
		vaddr, _ := r.u32(base+12, "VirtualAddress")
		rawSize, _ := r.u32(base+16, "SizeOfRawData")
		rawPtr, _ := r.u32(base+20, "PointerToRawData")
		flags, _ := r.u32(base+36, "Characteristics")

		if rawSize != 0 {
			end := int64(rawPtr) + int64(rawSize)
			if end < int64(rawPtr) || end > int64(len(r.data)) {
				return nil, &Error{Kind: KindCorrupt, Format: FormatPE,
					Offset: int64(rawPtr), Field: "PointerToRawData/SizeOfRawData",
					Msg: fmt.Sprintf("section %q raw data [%d,%d) lies outside %d-byte file",
						name, rawPtr, end, len(r.data))}
			}
		}
		out = append(out, Section{
			Name:     name,
			Address:  uint64(vaddr),
			Offset:   uint64(rawPtr),
			Size:     uint64(rawSize),
			Perm:     pePerm(flags),
			RawFlags: flags,
			RawType:  vsize,
		})
	}
	return out, nil
}

// peSectionName resolves an 8-byte on-disk section-name field. Names shorter
// than 8 bytes are NUL padded; longer names are encoded as "/" plus a decimal
// offset into the COFF string table.
func peSectionName(field []byte, strtab []byte) (string, error) {
	if field[0] == '/' {
		var off int64
		hasDigit := false
		for _, c := range field[1:] {
			if c == 0 {
				break
			}
			if c < '0' || c > '9' {
				return "", fmt.Errorf("long name reference %q is not a decimal offset", trimNUL(field))
			}
			off = off*10 + int64(c-'0')
			hasDigit = true
		}
		if !hasDigit {
			return "", fmt.Errorf("empty long-name offset")
		}
		// COFF string-table offsets are relative to the table start; the
		// table's first 4 bytes are its own size.
		if off < 0 || int(off) >= len(strtab) {
			return "", fmt.Errorf("name offset %d outside COFF string table (%d bytes)", off, len(strtab))
		}
		end := off
		for end < int64(len(strtab)) && strtab[end] != 0 {
			end++
		}
		if end >= int64(len(strtab)) {
			return "", fmt.Errorf("name at offset %d is not NUL terminated", off)
		}
		return string(strtab[off:end]), nil
	}
	end := 0
	for end < 8 && field[end] != 0 {
		end++
	}
	return string(field[:end]), nil
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func pePerm(flags uint32) Perm {
	var p Perm
	if flags&peSectionMemRead != 0 {
		p |= PermRead
	}
	if flags&peSectionMemWrite != 0 {
		p |= PermWrite
	}
	if flags&peSectionMemExecute != 0 {
		p |= PermExecute
	}
	return p
}

func archBits(a Arch) int {
	switch a {
	case ArchX86, ArchARM:
		return 32
	case ArchAMD64, ArchARM64:
		return 64
	default:
		return 0
	}
}

func markPE(err error) error {
	var pe *Error
	if errors.As(err, &pe) {
		if pe.Format == "" {
			pe.Format = FormatPE
		}
		return pe
	}
	return err
}
