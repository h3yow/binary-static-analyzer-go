package parser

func put16le(b []byte, off int, v uint16) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
}

func put32le(b []byte, off int, v uint32) {
	for i := 0; i < 4; i++ {
		b[off+i] = byte(v >> (8 * i))
	}
}

func put64le(b []byte, off int, v uint64) {
	for i := 0; i < 8; i++ {
		b[off+i] = byte(v >> (8 * i))
	}
}
