// Package binary defines the unified structural model produced by all
// executable-format parsers (ELF, PE, Mach-O).
package binary

// Format identifies the executable container format.
type Format string

// Supported container formats.
const (
	FormatELF   Format = "elf"
	FormatPE    Format = "pe"
	FormatMachO Format = "macho"
)

// Arch identifies the instruction-set architecture.
type Arch string

// Recognized architectures.
const (
	ArchX86     Arch = "x86"
	ArchAMD64   Arch = "amd64"
	ArchARM     Arch = "arm"
	ArchARM64   Arch = "arm64"
	ArchUnknown Arch = "unknown"
)

// FileType is the coarse role of the binary.
type FileType string

// Coarse binary types.
const (
	TypeUnknown       FileType = "unknown"
	TypeExecutable    FileType = "executable"
	TypeSharedLibrary FileType = "shared_library"
	TypeObject        FileType = "object"
	TypeCore          FileType = "core"
)

// Perm describes section permissions as unix-style bits.
type Perm uint8

// Permission bits.
const (
	PermRead    Perm = 4
	PermWrite   Perm = 2
	PermExecute Perm = 1
)

// String renders permissions in rwx form, e.g. "r-x".
func (p Perm) String() string {
	r := "-"
	w := "-"
	x := "-"
	if p&PermRead != 0 {
		r = "r"
	}
	if p&PermWrite != 0 {
		w = "w"
	}
	if p&PermExecute != 0 {
		x = "x"
	}
	return r + w + x
}

// Section is a format-neutral description of one section/segment.
type Section struct {
	Name     string
	Address  uint64
	Offset   uint64
	Size     uint64
	Perm     Perm
	RawFlags uint32
	RawType  uint32
}

// Binary is the unified structural model.
type Binary struct {
	Format     Format
	Arch       Arch
	Bits       int
	BigEndian  bool
	Type       FileType
	EntryPoint uint64
	Sections   []Section
	// Size is the total size of the source blob the binary was parsed from.
	Size int64
}
