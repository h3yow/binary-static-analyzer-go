package parser

import (
	"context"
	"strconv"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
)

// PE starts with an MS-DOS header; the PE signature is found via e_lfanew.
type peParser struct{}

func (p *peParser) Name() string { return string(model.FormatPE) }

func (p *peParser) Sniff(data []byte) bool {
	// Dispatch on the full DOS "MZ" magic; the PE signature and e_lfanew are
	// validated in Parse so a present-but-broken PE reports corrupt/
	// truncated rather than being lumped into unknown format.
	return len(data) >= 2 && data[0] == 'M' && data[1] == 'Z'
}

const (
	peSigLen    = 4
	coffHdrLen  = 20
	optMagic32  = 0x10b
	optMagic64  = 0x20b
	peSecHdrLen = 40
)

func (p *peParser) Parse(ctx context.Context, data []byte, opts Options) (*model.Binary, error) {
	const format = "pe"

	if len(data) < 2 {
		return nil, trunc(format, "file shorter than MZ signature", int64(len(data)))
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, corrupt(format, "missing MZ DOS signature", 0)
	}
	if len(data) < 0x40 {
		return nil, trunc(format, "DOS header incomplete (need 64 bytes for e_lfanew)", int64(len(data)))
	}
	peOff := int64(readUint32(data, 0x3c, true))
	if peOff <= 0 {
		return nil, corrupt(format, "e_lfanew is zero", 0x3c)
	}
	if peOff+peSigLen+coffHdrLen > int64(len(data)) {
		return nil, trunc(format, "PE/COFF header pointed to by e_lfanew exceeds file", peOff)
	}
	if data[peOff] != 'P' || data[peOff+1] != 'E' || data[peOff+2] != 0 || data[peOff+3] != 0 {
		return nil, corrupt(format, "missing PE\\0\\0 signature at e_lfanew", peOff)
	}

	coff := peOff + peSigLen
	machine := readUint16(data, int(coff)+0, true)
	numSections := int(readUint16(data, int(coff)+2, true))
	optSize := int64(readUint16(data, int(coff)+16, true))

	if numSections == 0 {
		return nil, corrupt(format, "COFF header declares zero sections", coff+2)
	}
	if opts.MaxSections > 0 && numSections > opts.MaxSections {
		return nil, &ParseError{Cause: ErrOversized, Format: format, Detail: "section count exceeds configured limit", Offset: coff}
	}
	if optSize == 0 {
		return nil, corrupt(format, "optional header size is zero", coff+16)
	}

	optOff := coff + coffHdrLen
	if optOff+optSize > int64(len(data)) {
		return nil, trunc(format, "optional header extends past end of file", int64(optOff))
	}
	optMagic := readUint16(data, int(optOff), true)
	is64 := false
	bits := 32
	entryOff := optOff + 16
	switch optMagic {
	case optMagic32:
		is64 = false
		bits = 32
	case optMagic64:
		is64 = true
		bits = 64
		// AddressOfEntryPoint is magic-invariant at +16; ImageBase differs.
	default:
		return nil, corrupt(format, "unsupported optional header magic (only PE32 0x10b / PE32+ 0x20b)", int64(optOff))
	}
	entry := uint64(readUint32(data, int(entryOff), true))
	_ = is64 // reflected in FormatDetail / Bits

	// Section table begins immediately after the optional header.
	secTableOff := optOff + optSize
	if int64(numSections)*peSecHdrLen > int64(len(data))-secTableOff {
		return nil, trunc(format, "section header table extends past end of file", secTableOff)
	}

	// Long names ("/123") refer to the COFF string table, located after the
	// symbol table: string table offset = ptrToSymbolTable + numberOfSymbols*18.
	symTabOff := int64(readUint32(data, int(coff)+8, true))
	numSyms := int64(readUint32(data, int(coff)+12, true))
	var strTab []byte
	if symTabOff > 0 {
		st := symTabOff + numSyms*18
		if st+4 <= int64(len(data)) {
			total := int64(readUint32(data, int(st), true))
			if st+total <= int64(len(data)) && total >= 4 {
				strTab = data[st : st+total]
			}
		}
	}

	sections := make([]model.Section, 0, numSections)
	for i := 0; i < numSections; i++ {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		base := secTableOff + int64(i)*peSecHdrLen
		rawName := cstring(data[int(base):int(base)+8], 0)
		virtualSize := uint64(readUint32(data, int(base)+8, true))
		addr := uint64(readUint32(data, int(base)+12, true))
		rawSize := uint64(readUint32(data, int(base)+16, true))
		rawPtr := uint64(readUint32(data, int(base)+20, true))
		flags := uint32(readUint32(data, int(base)+36, true))

		name := rawName
		if len(rawName) > 0 && rawName[0] == '/' {
			name = resolvePELongName(rawName[1:], strTab, i)
		}

		sec := model.Section{
			Name:    name,
			Address: addr,
			Offset:  rawPtr,
			Size:    rawSize,
			Flags:   flags,
		}
		_ = virtualSize
		if rawSize > 0 {
			if rawPtr > uint64(len(data)) || rawSize > uint64(len(data))-rawPtr {
				sec.Truncated = true
				return nil, trunc(format, "section "+orName(name, i)+" raw data extends past end of file", int64(rawPtr))
			}
			raw := data[rawPtr : rawPtr+rawSize]
			sec.Entropy = entropy(raw)
			if opts.MaxSectionBytes <= 0 || len(raw) <= opts.MaxSectionBytes {
				sec.Raw = raw
			}
		}
		sections = append(sections, sec)
	}

	return &model.Binary{
		Format:       model.FormatPE,
		FormatDetail: peDetail(optMagic),
		Arch:         peArch(machine),
		Bits:         bits,
		LittleEndian: true,
		EntryPoint:   entry,
		Sections:     sections,
	}, nil
}

func resolvePELongName(decimal string, strTab []byte, idx int) string {
	if len(strTab) == 0 {
		return "/$" + decimal
	}
	n, err := strconv.Atoi(decimal)
	if err != nil || n < 4 || n >= len(strTab) {
		return "/$" + decimal
	}
	return cstring(strTab, n)
}

func peDetail(magic uint16) string {
	if magic == optMagic64 {
		return "pe32+-little"
	}
	return "pe32-little"
}

func peArch(machine uint16) model.Architecture {
	switch machine {
	case 0x014c:
		return model.ArchX86
	case 0x8664:
		return model.ArchX86_64
	case 0x01c0, 0x01c2, 0x01c4:
		return model.ArchARM
	case 0xaa64:
		return model.ArchARM64
	default:
		return model.ArchUnknown
	}
}
