package asic

// TestWriteContainerLayout verifies the byte layout of the container writer
// against the ASiC-E magic requirements (PLAN.md §1.1).
//
// SELF-CONSISTENCY PIN: the assertions below are against this writer's own
// output. The byte-level layout comparison against the collector's
// fixture testEIDTS.bdoc (data-descriptor question: the fixture's
// mimetype entry has flags 0x0800, method stored, name length 8 at
// offset 26, zero extra field, and NO PK\x07\x08 data descriptor; the
// collector's first-entry magic check verifies all of those but not
// the flags byte, so our flags=0 entry is compliant) lives in
// the companion asice-compat harness.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"

	"github.com/beevik/etree"
)

// localHeaderFields extracts the ASiC-E-relevant local file header fields
// at offset 0 of a ZIP stream.
type zipLocalHeader struct {
	marker   string
	version  uint16
	flags    uint16
	method   uint16
	crc      uint32
	csize    uint32
	usize    uint32
	nameLen  uint16
	extraLen uint16
	name     string
}

func localHeaderFields(t *testing.T, b []byte) zipLocalHeader {
	t.Helper()
	if len(b) < 38 {
		t.Fatalf("archive shorter than a local header: %d bytes", len(b))
	}
	le := binary.LittleEndian
	f := zipLocalHeader{
		marker:   string(b[:4]),
		version:  le.Uint16(b[4:6]),
		flags:    le.Uint16(b[6:8]),
		method:   le.Uint16(b[8:10]),
		crc:      le.Uint32(b[14:18]),
		csize:    le.Uint32(b[18:22]),
		usize:    le.Uint32(b[22:26]),
		nameLen:  le.Uint16(b[26:28]),
		extraLen: le.Uint16(b[28:30]),
	}
	end := 30 + int(f.nameLen)
	if len(b) < end {
		t.Fatalf("archive shorter than local header + name: %d bytes", len(b))
	}
	f.name = string(b[30:end])
	return f
}

func TestWriteContainerLayout(t *testing.T) {
	var buf bytes.Buffer
	err := WriteContainer(&buf, []Doc{{
		Name:      "test.txt",
		MediaType: "application/octet-stream",
		Data:      []byte("hello ASiC-E"),
	}}, []byte("<xml/>"))
	if err != nil {
		t.Fatalf("WriteContainer: %v", err)
	}
	b := buf.Bytes()

	// --- mimetype magic entry (the collector's first-entry magic check) ---
	f := localHeaderFields(t, b)
	if f.marker != "PK\x03\x04" {
		t.Errorf("marker: got %q", f.marker)
	}
	if f.name != "mimetype" || f.nameLen != 8 {
		t.Errorf("magic entry name: got %q len %d (want \"mimetype\", 8)", f.name, f.nameLen)
	}
	if f.method != 0 {
		t.Errorf("magic entry method: got %d, want 0 (stored)", f.method)
	}
	if f.extraLen != 0 {
		t.Errorf("magic entry extra field length: got %d, want 0", f.extraLen)
	}
	if int(f.csize) != len(MimeTypeContent) || f.csize != f.usize {
		t.Errorf("magic entry sizes: got comp %d uncomp %d, want %d", f.csize, f.usize, len(MimeTypeContent))
	}
	wantCRC := crc32.ChecksumIEEE([]byte(MimeTypeContent))
	if f.crc != wantCRC {
		t.Errorf("magic entry CRC: got %#x, want %#x", f.crc, wantCRC)
	}
	if got := string(b[38 : 38+len(MimeTypeContent)]); got != MimeTypeContent {
		t.Errorf("magic entry content: got %q", got)
	}

	// --- data descriptor question: no PK\x07\x08 anywhere in the archive ---
	if i := bytes.Index(b, []byte("PK\x07\x08")); i >= 0 {
		t.Errorf("data descriptor PK\\x07\\x08 found at offset %d; must be absent", i)
	}
	// (The previous attempt's archive/zip experiment set flags 0x0008 and
	// emitted a descriptor after the data; ours sets flags 0 and emits none.
	// The fixture sets flags 0x0800 and also emits none.)

	// --- central directory: first entry is the magic entry at offset 38 ---
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	if len(zr.File) != 4 {
		t.Fatalf("entries: got %d, want 4", len(zr.File))
	}
	mime := zr.File[0]
	if mime.Name != "mimetype" {
		t.Errorf("first central entry: got %q", mime.Name)
	}
	off, err := mime.DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	if off != 38 {
		t.Errorf("magic entry data offset: got %d, want 38 (30 + name length 8)", off)
	}
	if mime.Method != zip.Store || mime.CompressedSize64 != uint64(len(MimeTypeContent)) || len(mime.Extra) != 0 {
		t.Errorf("magic central entry: method=%d compSize=%d extraLen=%d",
			mime.Method, mime.CompressedSize64, len(mime.Extra))
	}

	// --- entry order and round-trip content ---
	wantNames := []string{"mimetype", "META-INF/manifest.xml", "test.txt", "META-INF/signatures0.xml"}
	for i, zf := range zr.File {
		if zf.Name != wantNames[i] {
			t.Errorf("entry %d name: got %q, want %q", i, zf.Name, wantNames[i])
		}
		if zf.Method != zip.Store {
			t.Errorf("entry %s: method %d, want stored", zf.Name, zf.Method)
		}
	}
	r, err := zr.File[2].Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello ASiC-E" {
		t.Errorf("data file content: got %q", data)
	}

	// --- EOCD: exactly 22 bytes at the end, nothing after ---
	eocd := b[len(b)-22:]
	if string(eocd[:4]) != "PK\x05\x06" {
		t.Errorf("EOCD marker: got %q", eocd[:4])
	}
	if n := binary.LittleEndian.Uint16(eocd[10:12]); n != 4 {
		t.Errorf("EOCD entry count: got %d, want 4", n)
	}
	cdOff := int64(binary.LittleEndian.Uint32(eocd[16:20]))
	cdSize := binary.LittleEndian.Uint32(eocd[12:16])
	if int(cdOff)+int(cdSize) != len(b)-22 {
		t.Errorf("central directory [offset %d, +size %d] does not end at EOCD start %d",
			cdOff, cdSize, len(b)-22)
	}
	if binary.LittleEndian.Uint16(eocd[20:22]) != 0 {
		t.Errorf("EOCD comment length: want 0")
	}

	// --- manifest content: ODF v1.0 structure (layout is house style, ADR 0005) ---
	r, err = zr.File[1].Open()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	m := etree.NewDocument()
	if err := m.ReadFromBytes(manifest); err != nil {
		t.Fatalf("manifest does not parse as XML: %v", err)
	}
	mroot := m.Root()
	if mroot.FullTag() != "manifest:manifest" || mroot.SelectAttrValue("xmlns:manifest", "") != nsODFManifest {
		t.Errorf("manifest root: got %s xmlns:manifest=%q", mroot.FullTag(), mroot.SelectAttrValue("xmlns:manifest", ""))
	}
	entries := mroot.ChildElements()
	if len(entries) != 2 {
		t.Fatalf("manifest entries: got %d, want 2", len(entries))
	}
	for i, want := range [][2]string{{"/", MimeTypeContent}, {"test.txt", "application/octet-stream"}} {
		e := entries[i]
		if e.FullTag() != "manifest:file-entry" {
			t.Errorf("entry %d tag: got %s", i, e.FullTag())
			continue
		}
		if got := e.SelectAttrValue("manifest:full-path", ""); got != want[0] {
			t.Errorf("entry %d full-path: got %q, want %q", i, got, want[0])
		}
		if got := e.SelectAttrValue("manifest:media-type", ""); got != want[1] {
			t.Errorf("entry %d media-type: got %q, want %q", i, got, want[1])
		}
	}
}
