package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeFixtureELF creates a tiny ELF64 LE file containing the byte string
// "SECRET" inside its .data section.
func writeFixtureELF(t *testing.T, dir, name string) string {
	t.Helper()
	names := "\x00.text\x00.data\x00.shstrtab\x00"
	nameOff := func(s string) uint32 { return uint32(bytes.Index([]byte(names), []byte(s))) }
	textBody := []byte{0xc3}
	dataBody := []byte("SECRET")
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x7f, 'E', 'L', 'F'
	hdr[4], hdr[5], hdr[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(hdr[16:], 2)
	le.PutUint16(hdr[18:], 0x3e)
	le.PutUint32(hdr[20:], 1)
	le.PutUint64(hdr[24:], 0x401000)
	le.PutUint16(hdr[58:], 64)
	le.PutUint16(hdr[60:], 4)
	le.PutUint16(hdr[62:], 3)
	var buf bytes.Buffer
	buf.Write(hdr)
	to := uint64(buf.Len())
	buf.Write(textBody)
	do := uint64(buf.Len())
	buf.Write(dataBody)
	so := uint64(buf.Len())
	buf.WriteString(names)
	shoff := uint64(buf.Len())
	buf.Write(make([]byte, 64))
	sh := func(name uint32, typ uint32, flags uint64, addr, off, size uint64) {
		b := make([]byte, 64)
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[8:], flags)
		le.PutUint64(b[16:], addr)
		le.PutUint64(b[24:], off)
		le.PutUint64(b[32:], size)
		buf.Write(b)
	}
	sh(nameOff(".text"), 1, 2|4, 0x401000, to, 1)
	sh(nameOff(".data"), 1, 2, 0x402000, do, uint64(len(dataBody)))
	sh(nameOff(".shstrtab"), 3, 0, 0, so, uint64(len(names)))
	out := buf.Bytes()
	le.PutUint64(out[40:], shoff)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, out, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

type report struct {
	RuleSetHash string `json:"rule_set_hash"`
	Results     []struct {
		Target string `json:"target"`
		Status string `json:"status"`
		Cached bool   `json:"cached"`
		Error  *struct {
			Kind string `json:"kind"`
		} `json:"error"`
		Findings []struct {
			RuleID  string `json:"rule_id"`
			Basis   string `json:"basis"`
			Matched string `json:"matched"`
		} `json:"findings"`
	} `json:"results"`
}

func TestCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	good := writeFixtureELF(t, dir, "good.elf")
	bad := filepath.Join(dir, "trunc.bin")
	if err := os.WriteFile(bad, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules.json")
	body := `{
	  "id":"cli","version":"v9",
	  "rules":[
	    {"id":"S","version":"1","name":"secret","severity":"high",
	     "target":"file_content","op":"contains","value":"SECRET"}
	  ]
	}`
	if err := os.WriteFile(rules, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// run() writes JSON to os.Stdout; capture it by redirecting within a
	// subprocess-free call: invoke run and parse a temp file instead by
	// capturing stdout through os.Pipe.
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"-rules", rules, good, bad})
	w.Close()
	os.Stdout = old
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 because one target failed to parse", code)
	}
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.RuleSetHash == "" {
		t.Fatal("missing rule set hash")
	}
	if len(rep.Results) != 2 || rep.Results[0].Target != good || rep.Results[1].Target != bad {
		t.Fatalf("unexpected report order/content: %+v", rep.Results)
	}
	if rep.Results[0].Status != "ok" || len(rep.Results[0].Findings) != 1 ||
		rep.Results[0].Findings[0].RuleID != "S" {
		t.Fatalf("good target verdict: %+v", rep.Results[0])
	}
	if rep.Results[1].Status != "parse_failed" || rep.Results[1].Error.Kind != "truncated" {
		t.Fatalf("bad target verdict: %+v", rep.Results[1])
	}
	t.Logf("input=[%s, %s]; good basis=%q matched=%q; truncated kind=%s",
		good, bad, rep.Results[0].Findings[0].Basis,
		rep.Results[0].Findings[0].Matched, rep.Results[1].Error.Kind)
}

func TestCLIConfigErrors(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("no args: exit=%d want 2", code)
	}
	if code := run([]string{"-rules", "/nonexistent/rules.json", "/bin/true"}); code != 2 {
		t.Fatalf("missing rules file: exit=%d want 2", code)
	}
}
