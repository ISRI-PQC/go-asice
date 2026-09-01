// Package asic — limits on the untrusted container-read path:
// duplicate META-INF entry names rejected the same way as the other
// duplicate branches (the collector's container open rejects
// duplicates uniformly), and the per-entry / aggregate
// uncompressed-size caps that keep a hostile zip bomb from exhausting
// memory before verification runs.

package asic

import (
	"testing"
)

// TestVerifyDuplicateMetaInfEntries: a second META-INF/manifest.xml
// or a second META-INF/signaturesN.xml entry must be rejected with
// the same "duplicate entry name" error the mimetype and data-file
// branches use (a last-wins overwrite is an interop bypass).
func TestVerifyDuplicateMetaInfEntries(t *testing.T) {
	h := newVerifyHarness(t)
	manifest, err := manifestXML(h.docs)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		entries []miniEntry
	}{
		{
			name: "DuplicateManifest",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: ManifestFile, Data: manifest},
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: ManifestFile, Data: manifest},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
		},
		{
			name: "DuplicateSignature",
			entries: []miniEntry{
				{Name: "mimetype", Data: []byte(MimeTypeContent)},
				{Name: ManifestFile, Data: manifest},
				{Name: "test.txt", Data: h.docs[0].Data},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
				{Name: "META-INF/signatures0.xml", Data: h.sig},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFail(t, h.path(t, miniStoredZIP(tc.entries)), h.opts(), "duplicate entry name")
		})
	}
}

// TestVerifyUncompressedSizeLimits: a hostile container whose entry
// (per-entry cap) or entries (aggregate cap) decompress beyond the
// limits must be rejected fail-closed with the size-limit errors
// instead of exhausting memory. The caps are vars, so the test
// shrinks them to a few MiB (production defaults are 64/256 MiB).
func TestVerifyUncompressedSizeLimits(t *testing.T) {
	oldEntry, oldTotal := maxEntryUncompressed, maxTotalUncompressed
	maxEntryUncompressed = 4 << 20
	maxTotalUncompressed = 6 << 20
	t.Cleanup(func() {
		maxEntryUncompressed, maxTotalUncompressed = oldEntry, oldTotal
	})
	h := newVerifyHarness(t)
	manifest, err := manifestXML(h.docs)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("PerEntry", func(t *testing.T) {
		big := make([]byte, maxEntryUncompressed+1) // one byte over the cap (zeros)
		entries := []miniEntry{
			{Name: "mimetype", Data: []byte(MimeTypeContent)},
			{Name: ManifestFile, Data: manifest},
			{Name: "test.txt", Data: big},
			{Name: "META-INF/signatures0.xml", Data: h.sig},
		}
		expectFail(t, h.path(t, miniStoredZIP(entries)), h.opts(), "byte uncompressed limit")
	})

	t.Run("Aggregate", func(t *testing.T) {
		b1 := make([]byte, maxEntryUncompressed) // within the per-entry cap
		b2 := make([]byte, maxTotalUncompressed-maxEntryUncompressed+1)
		entries := []miniEntry{
			{Name: "mimetype", Data: []byte(MimeTypeContent)},
			{Name: ManifestFile, Data: manifest},
			{Name: "big1.txt", Data: b1},
			{Name: "big2.txt", Data: b2},
			{Name: "META-INF/signatures0.xml", Data: h.sig},
		}
		expectFail(t, h.path(t, miniStoredZIP(entries)), h.opts(), "container exceeds the uncompressed size limit")
	})
}
