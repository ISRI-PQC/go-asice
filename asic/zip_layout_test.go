package asic

import (
	"archive/zip"
	"bytes"
	"fmt"
	"hash/crc32"
	"testing"
)

// TestZipLayout scratch: verify local header layout of a stored entry.
func TestZipLayout(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	data := []byte("application/vnd.etsi.asic-e+zip")
	fh := &zip.FileHeader{
		Name:               "mimetype",
		Method:             zip.Store,
		CompressedSize64:   uint64(len(data)),
		UncompressedSize64: uint64(len(data)),
		CRC32:              crc32.ChecksumIEEE(data),
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	fmt.Printf("total %d bytes\n", len(b))
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Printf("%04x: % x\n", i, b[i:end])
	}
}
