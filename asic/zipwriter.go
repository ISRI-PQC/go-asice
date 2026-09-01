// Package asic builds ASiC-E containers (TS 102 918 §6.2, XML/XAdES form)
// in the layout the Estonian e-voting collector accepts.
//
// This file implements the ZIP container writer. Go's archive/zip is not
// used to WRITE the container because it unconditionally sets general
// purpose bit 3 (data descriptor) and emits a PK\x07\x08 data descriptor
// after each entry; the ASiC-E "mimetype" magic entry (and the
// reference fixtures) carry no data descriptor. The writer below
// hand-writes the
// local file headers, central directory, and EOCD for stored entries only,
// which is all an ASiC-E container needs (mimetype must be stored; the
// other entries are stored too, for determinism).
package asic

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

// Container constants fixed by the ASiC-E / BDOC interop contract (see
// PLAN.md §1.1 and ADR 0001 section 2).
const (
	// MimeTypeFile is the name of the magic file, which must be the first
	// entry of the archive.
	MimeTypeFile = "mimetype"

	// MimeTypeContent is the exact required content of the magic file.
	MimeTypeContent = "application/vnd.etsi.asic-e+zip"

	// ManifestFile is the ODF v1.0 manifest entry path.
	ManifestFile = "META-INF/manifest.xml"

	// SignatureFilePrefix is the META-INF prefix for signature files
	// (signatures0.xml, signatures1.xml, ...). The collector's parser
	// matches
	// ^META-INF/[^/]*signatures[^/]*\.xml$ case-sensitively.
	SignatureFilePrefix = "META-INF/signatures"
)

// Doc is one data file of the container.
type Doc struct {
	// Name is the flat file name (no path separators).
	Name string
	// MediaType is the ODF manifest media type for the file
	// (e.g. "application/octet-stream").
	MediaType string
	// Data is the raw file content.
	Data []byte
}

// zipEntry is one stored (uncompressed) archive member.
type zipEntry struct {
	name   string
	data   []byte
	crc    uint32
	offset int // local header offset; filled while writing
}

// Fixed DOS time/date for all entries (1980-01-01 00:00:00, the minimum
// valid ZIP date) so that container bytes depend only on content.
const (
	dosTime = 0x0000
	dosDate = 0x0021
)

// writeContainerZIP writes the ASiC-E ZIP to w: the mimetype magic entry
// first, then META-INF/manifest.xml, then the data files in the given
// order, then the signature files (signatures0.xml, ...). Nothing is
// written after the end-of-central-directory record.
func writeContainerZIP(w io.Writer, manifest []byte, docs []Doc, sigs [][]byte) error {
	entries := make([]zipEntry, 0, 2+len(docs)+len(sigs))
	entries = append(entries, zipEntry{name: MimeTypeFile, data: []byte(MimeTypeContent)})
	entries = append(entries, zipEntry{name: ManifestFile, data: manifest})
	for i := range docs {
		d := docs[i]
		if err := checkDocName(d.Name); err != nil {
			return err
		}
		entries = append(entries, zipEntry{name: d.Name, data: d.Data})
	}
	for i, s := range sigs {
		entries = append(entries, zipEntry{name: SignatureFilePrefix + fmt.Sprint(i) + ".xml", data: s})
	}

	// Classic (non-ZIP64) ZIP fields are fixed-width: an unchecked
	// narrowing conversion past the limit would wrap silently and emit a
	// container whose metadata disagrees with its bytes, so validate
	// before writing anything (see checkZIPBounds).
	total := 22 // EOCD
	maxName, maxData := 0, 0
	for i := range entries {
		e := &entries[i]
		total += 76 + 2*len(e.name) + len(e.data) // 30-byte local + 46-byte central header, name twice, data once
		if total > math.MaxUint32 {
			total = math.MaxUint32 + 1 // cap; any larger total is rejected the same
			break
		}
		if len(e.name) > maxName {
			maxName = len(e.name)
		}
		if len(e.data) > maxData {
			maxData = len(e.data)
		}
	}
	if err := checkZIPBounds(maxName, maxData, len(entries), total); err != nil {
		return err
	}

	var b []byte // assembled locally so offsets are known before writing
	for i := range entries {
		e := &entries[i]
		e.crc = crc32.ChecksumIEEE(e.data)
		e.offset = len(b)

		var lh [30]byte
		binary.LittleEndian.PutUint32(lh[0:4], 0x04034b50) // local file header
		binary.LittleEndian.PutUint16(lh[4:6], 20)         // version needed
		binary.LittleEndian.PutUint16(lh[6:8], 0)          // flags: no data descriptor
		binary.LittleEndian.PutUint16(lh[8:10], 0)         // method: stored
		binary.LittleEndian.PutUint16(lh[10:12], dosTime)
		binary.LittleEndian.PutUint16(lh[12:14], dosDate)
		binary.LittleEndian.PutUint32(lh[14:18], e.crc)
		binary.LittleEndian.PutUint32(lh[18:22], uint32(len(e.data))) // compressed size
		binary.LittleEndian.PutUint32(lh[22:26], uint32(len(e.data))) // uncompressed size
		binary.LittleEndian.PutUint16(lh[26:28], uint16(len(e.name)))
		binary.LittleEndian.PutUint16(lh[28:30], 0) // no extra field
		b = append(b, lh[:]...)
		b = append(b, e.name...)
		b = append(b, e.data...)
	}

	cdStart := len(b)
	for i := range entries {
		e := &entries[i]
		var ch [46]byte
		binary.LittleEndian.PutUint32(ch[0:4], 0x02014b50) // central directory header
		binary.LittleEndian.PutUint16(ch[4:6], 20)         // version made by
		binary.LittleEndian.PutUint16(ch[6:8], 20)         // version needed
		binary.LittleEndian.PutUint16(ch[8:10], 0)         // flags
		binary.LittleEndian.PutUint16(ch[10:12], 0)        // method: stored
		binary.LittleEndian.PutUint16(ch[12:14], dosTime)
		binary.LittleEndian.PutUint16(ch[14:16], dosDate)
		binary.LittleEndian.PutUint32(ch[16:20], e.crc)
		binary.LittleEndian.PutUint32(ch[20:24], uint32(len(e.data)))
		binary.LittleEndian.PutUint32(ch[24:28], uint32(len(e.data)))
		binary.LittleEndian.PutUint16(ch[28:30], uint16(len(e.name)))
		// extra, comment, disk number, attributes: zero
		binary.LittleEndian.PutUint32(ch[42:46], uint32(e.offset))
		b = append(b, ch[:]...)
		b = append(b, e.name...)
	}
	cdSize := len(b) - cdStart

	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50) // end of central directory
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(len(entries)))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(len(entries)))
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(cdSize))
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdStart))
	// comment length: zero
	b = append(b, eocd[:]...)

	_, err := w.Write(b)
	return err
}

// checkDocName rejects names that would break the flat ASiC-E layout.
func checkDocName(name string) error {
	if name == "" {
		return fmt.Errorf("asic: document name is empty")
	}
	for _, r := range name {
		if r == '/' || r == '\\' {
			return fmt.Errorf("asic: document name %q must be flat (no subfolders)", name)
		}
	}
	if name == MimeTypeFile || name == "META-INF" {
		return fmt.Errorf("asic: document name %q is reserved", name)
	}
	return nil
}

// checkZIPBounds reports an error if any container content would overflow
// a fixed-width field of the classic (non-ZIP64) ZIP format that
// writeContainerZIP emits: an entry name of more than math.MaxUint16
// bytes (uint16 name fields in the local and central directory headers),
// entry data of more than math.MaxUint32 bytes (uint32 size fields), more
// than math.MaxUint16 entries (uint16 entry-count fields in the EOCD), or
// a total archive size above math.MaxUint32 bytes (uint32 offset/size
// fields in the central directory and EOCD). Exact fits are allowed; only
// values past the maxima are rejected. The ASiC-E interop target reads
// classic ZIP, so the writer rejects oversized input instead of
// upgrading to ZIP64.
func checkZIPBounds(nameLen, dataLen, entryCount, totalBytes int) error {
	if nameLen > math.MaxUint16 {
		return fmt.Errorf("asic: entry name of %d bytes exceeds the %d-byte ZIP name field limit", nameLen, math.MaxUint16)
	}
	if dataLen > math.MaxUint32 {
		return fmt.Errorf("asic: entry data of %d bytes exceeds the %d-byte ZIP size field limit", dataLen, math.MaxUint32)
	}
	if entryCount > math.MaxUint16 {
		return fmt.Errorf("asic: %d entries exceeds the %d-entry ZIP central directory limit", entryCount, math.MaxUint16)
	}
	if totalBytes > math.MaxUint32 {
		return fmt.Errorf("asic: archive of %d bytes exceeds the %d-byte ZIP offset/size limit", totalBytes, math.MaxUint32)
	}
	return nil
}
