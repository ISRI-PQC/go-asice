// Hostile-input XML escaping regression test (Task 2+3 add-on).
//
// A data file name and media type carrying XML-hostile characters (& < >
// " ') must survive the FULL render path (SignBES + WriteContainer) and
// round-trip to values EQUAL to the inputs through both the ODF manifest
// and the signature document.
//
// The point is the escape round-trip: an unescaped & would terminate the
// attribute early, an unescaped < would start a bogus element, and an
// unescaped " would break the attribute quote — each corrupts the
// document so the parsed value no longer equals the input. (The
// collector's structural-acceptance check on the same container now
// lives in the companion asice-compat harness.)
package asic

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/isri-pqc/asice/testutil"
)

// TestHostileNameEscapesRoundTrips drives a file name and media type full
// of XML metacharacters through SignBES + WriteContainer and asserts the
// values round-trip through the manifest and signature documents.
func TestHostileNameEscapesRoundTrips(t *testing.T) {
	const hostileName = `a&b<1>"q'.txt`
	const hostileMT = `text/x;param="v&w"`
	T := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	p, err := testutil.NewPKI(testutil.Options{Now: T})
	if err != nil {
		t.Fatal(err)
	}

	docs := []Doc{{Name: hostileName, MediaType: hostileMT, Data: []byte("hostile")}}
	sig, err := SignBES(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, T)
	if err != nil {
		t.Fatalf("asic.SignBES: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteContainer(&buf, docs, sig); err != nil {
		t.Fatalf("asic.WriteContainer: %v", err)
	}
	container := buf.Bytes()

	// (1) encoding/xml round-trip of the manifest and the signature doc.
	manifest, err := containerEntry(container, ManifestFile)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	entries, err := parseODFManifest(manifest)
	if err != nil {
		t.Fatalf("manifest does not parse as XML: %v", err)
	}
	me := findEntry(entries, hostileName)
	if me == nil {
		t.Fatalf("no manifest file-entry round-trips to %q (parsed %d entries)", hostileName, len(entries))
	}
	if me.MediaType != hostileMT {
		t.Errorf("manifest media-type = %q, want %q", me.MediaType, hostileMT)
	}

	sigDoc, err := containerEntry(container, "META-INF/signatures0.xml")
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	refs, mt, err := parseSigDoc(sigDoc)
	if err != nil {
		t.Fatalf("signature document does not parse as XML: %v", err)
	}
	if got := refFileURI(refs, hostileName); got == "" {
		t.Errorf("no ds:Reference URI round-trips to the hostile file name %q", hostileName)
	}
	if got := mt; got != hostileMT {
		t.Errorf("xades:MimeType = %q, want %q", got, hostileMT)
	}
}

// --- helpers ---

func containerEntry(container []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, &zipError{name: name}
}

type zipError struct{ name string }

func (e *zipError) Error() string { return "no entry " + e.name }

// ODF manifest shapes (manifest.xml). Parsed by token walk: attributes
// are matched by local name (the decoder unescapes the value), which is
// robust to the attribute's namespace prefix.
type odfFileEntry struct {
	FullPath  string
	MediaType string
}

func parseODFManifest(b []byte) ([]odfFileEntry, error) {
	var entries []odfFileEntry
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "file-entry" {
			continue
		}
		var e odfFileEntry
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "full-path":
				e.FullPath = a.Value
			case "media-type":
				e.MediaType = a.Value
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func findEntry(entries []odfFileEntry, name string) *odfFileEntry {
	for i := range entries {
		if entries[i].FullPath == name {
			return &entries[i]
		}
	}
	return nil
}

// signature document shapes: the hostile-value sites are the
// ds:Reference URI attribute (data-file reference) and the
// xades:MimeType element text. Parsed by token walk.
type sigRef struct {
	Id  string
	URI string
}

func parseSigDoc(b []byte) ([]sigRef, string, error) {
	var refs []sigRef
	var mt string
	inMT := false
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, "", err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			switch tok.Name.Local {
			case "Reference":
				var r sigRef
				for _, a := range tok.Attr {
					switch a.Name.Local {
					case "Id":
						r.Id = a.Value
					case "URI":
						r.URI = a.Value
					}
				}
				refs = append(refs, r)
			case "MimeType":
				inMT = true
			}
		case xml.EndElement:
			if tok.Name.Local == "MimeType" {
				inMT = false
			}
		case xml.CharData:
			if inMT {
				mt += string(tok)
			}
		}
	}
	return refs, mt, nil
}

// refFileURI returns the URI of the data-file reference — the reference
// whose URI, with a leading "#" (URI fragment indicator) stripped, equals
// name — or "" if absent. The "#" is stripped because the data-file
// reference is a relative URI to the zip entry name; the fragment form is
// an orthogonal convention (the SignedProperties reference uses it).
func refFileURI(refs []sigRef, name string) string {
	for _, r := range refs {
		if strings.TrimPrefix(r.URI, "#") == name {
			return r.URI
		}
	}
	return ""
}
