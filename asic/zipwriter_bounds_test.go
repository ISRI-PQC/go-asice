package asic

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// TestCheckZIPBounds: exact fits pass; any single field past its
// classic-ZIP limit is rejected (data/entry-count limits are exercised
// with synthesized lengths, not real 4 GiB allocations or 65536 entries).
func TestCheckZIPBounds(t *testing.T) {
	if err := checkZIPBounds(math.MaxUint16, math.MaxUint32, math.MaxUint16, math.MaxUint32); err != nil {
		t.Fatalf("checkZIPBounds at exact limits = %v, want nil", err)
	}
	cases := []struct {
		what        string
		nameLen     int
		dataLen     int
		entryCount  int
		totalBytes  int
		wantErrPart string
	}{
		{"name overflow", math.MaxUint16 + 1, 0, 0, 0, "name field limit"},
		{"data overflow", 0, math.MaxUint32 + 1, 0, 0, "size field limit"},
		{"entry count overflow", 0, 0, math.MaxUint16 + 1, 0, "central directory limit"},
		{"total size overflow", 0, 0, 0, math.MaxUint32 + 1, "offset/size limit"},
	}
	for _, c := range cases {
		err := checkZIPBounds(c.nameLen, c.dataLen, c.entryCount, c.totalBytes)
		if err == nil {
			t.Errorf("%s: checkZIPBounds = nil, want error", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrPart) {
			t.Errorf("%s: error %q does not mention %q", c.what, err, c.wantErrPart)
		}
	}
}

// TestWriteContainerBoundsName: a 65536-byte document name must be
// rejected with an error and must write no container bytes at all.
func TestWriteContainerBoundsName(t *testing.T) {
	long := strings.Repeat("a", math.MaxUint16+1)
	var buf bytes.Buffer
	err := WriteContainer(&buf, []Doc{{Name: long, MediaType: "application/octet-stream"}}, []byte("<sig/>"))
	if err == nil {
		t.Fatalf("WriteContainer with %d-byte name = nil, want error", len(long))
	}
	if buf.Len() != 0 {
		t.Fatalf("WriteContainer wrote %d bytes before failing, want 0", buf.Len())
	}
}
