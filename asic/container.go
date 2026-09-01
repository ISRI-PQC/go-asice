// Container-level API of the asic package: build a complete ASiC-E
// container (magic entry, ODF manifest, signature files, data files)
// from in-memory content.
package asic

import (
	"fmt"
	"io"

	"github.com/beevik/etree"
)

// WriteContainer writes a complete ASiC-E container to w.
//
// docs are the data files (≥1); sigs are pre-rendered XAdES signature XML
// documents, written as META-INF/signatures0.xml, META-INF/signatures1.xml,
// ... in the given order (≥1). Every data file must have a media type; the
// ODF manifest lists a "/" root entry plus one file-entry per data file.
// The container layout is deterministic: fixed entry order and fixed DOS
// dates, no data descriptors, no bytes after the EOCD record.
func WriteContainer(w io.Writer, docs []Doc, sigs ...[]byte) error {
	if len(docs) == 0 {
		return fmt.Errorf("asic: container needs at least one data file")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("asic: container needs at least one signature")
	}
	seen := make(map[string]struct{}, len(docs)+len(sigs)+2)
	seen[MimeTypeFile] = struct{}{}
	seen[ManifestFile] = struct{}{}
	for i := range sigs {
		seen[SignatureFilePrefix+fmt.Sprint(i)+".xml"] = struct{}{}
	}
	for i := range docs {
		d := docs[i]
		if d.MediaType == "" {
			return fmt.Errorf("asic: document %q has no media type", d.Name)
		}
		if _, ok := seen[d.Name]; ok {
			return fmt.Errorf("asic: duplicate file name %q", d.Name)
		}
		seen[d.Name] = struct{}{}
	}

	manifest, err := manifestXML(docs)
	if err != nil {
		return err
	}
	return writeContainerZIP(w, manifest, docs, sigs)
}

// manifestXML renders the ODF v1.0 manifest: a "/" root entry with the
// ASiC-E media type plus one file-entry per data file, in document order.
// The layout is house style (2-space indentation; ADR 0005).
func manifestXML(docs []Doc) ([]byte, error) {
	doc := etree.NewDocument()
	doc.AddChild(etree.NewProcInst("xml", xmlDeclInst))
	root := doc.CreateElement("manifest:manifest")
	root.CreateAttr("xmlns:manifest", nsODFManifest)
	addManifestEntry(root, "/", MimeTypeContent)
	for i := range docs {
		addManifestEntry(root, docs[i].Name, docs[i].MediaType)
	}
	doc.Indent(2)
	s, err := doc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("asic: manifest: %w", err)
	}
	return []byte(s), nil
}

// addManifestEntry appends one manifest:file-entry with the given
// full-path and media type (etree escapes the attribute values).
func addManifestEntry(root *etree.Element, fullPath, mediaType string) {
	e := root.CreateElement("manifest:file-entry")
	e.CreateAttr("manifest:full-path", fullPath)
	e.CreateAttr("manifest:media-type", mediaType)
}
