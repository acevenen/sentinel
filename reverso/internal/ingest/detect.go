package ingest

import (
	"encoding/binary"
	"net/http"
	"strings"
)

// ArtifactClass is REVerso's coarse classification of an artifact, used to
// route it to the right (future) analysis worker. Detection is best-effort and
// based only on magic bytes and the original extension; it never executes or
// trusts the artifact.
type ArtifactClass string

// Recognized artifact classes.
const (
	ClassELF        ArtifactClass = "executable_elf"
	ClassPE         ArtifactClass = "executable_pe"
	ClassPCAP       ArtifactClass = "pcap"
	ClassPCAPNG     ArtifactClass = "pcapng"
	ClassSquashFS   ArtifactClass = "squashfs"
	ClassUBoot      ArtifactClass = "uboot_image"
	ClassDeviceTree ArtifactClass = "device_tree"
	ClassGzip       ArtifactClass = "gzip"
	ClassZip        ArtifactClass = "archive_zip"
	ClassCSV        ArtifactClass = "csv"
	ClassJSON       ArtifactClass = "json"
	ClassYAML       ArtifactClass = "yaml"
	ClassText       ArtifactClass = "text"
	ClassUnknown    ArtifactClass = "unknown"
)

// Detection is the result of classifying an artifact.
type Detection struct {
	Class     ArtifactClass
	MediaType string
}

// Detect classifies data using magic bytes first, then the filename extension
// as a hint for text formats. It reads only the provided bytes.
func Detect(name string, data []byte) Detection {
	media := http.DetectContentType(data)
	if c, ok := detectMagic(data); ok {
		return Detection{Class: c, MediaType: media}
	}
	if c, ok := detectByExtension(name); ok {
		return Detection{Class: c, MediaType: media}
	}
	if looksTextual(data) {
		return Detection{Class: ClassText, MediaType: media}
	}
	return Detection{Class: ClassUnknown, MediaType: media}
}

func detectMagic(d []byte) (ArtifactClass, bool) {
	if len(d) >= 4 {
		if d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F' {
			return ClassELF, true
		}
		be := binary.BigEndian.Uint32(d[:4])
		le := binary.LittleEndian.Uint32(d[:4])
		switch {
		case be == 0xa1b2c3d4 || le == 0xa1b2c3d4 || be == 0xa1b23c4d || le == 0xa1b23c4d:
			return ClassPCAP, true
		case be == 0x0a0d0d0a:
			return ClassPCAPNG, true
		case be == 0x27051956:
			return ClassUBoot, true
		case be == 0xd00dfeed:
			return ClassDeviceTree, true
		}
		if d[0] == 'h' && d[1] == 's' && d[2] == 'q' && d[3] == 's' {
			return ClassSquashFS, true
		}
		if d[0] == 's' && d[1] == 'q' && d[2] == 's' && d[3] == 'h' {
			return ClassSquashFS, true
		}
	}
	if len(d) >= 2 {
		if d[0] == 'M' && d[1] == 'Z' {
			return ClassPE, true
		}
		if d[0] == 0x1f && d[1] == 0x8b {
			return ClassGzip, true
		}
		if d[0] == 'P' && d[1] == 'K' {
			return ClassZip, true
		}
	}
	return "", false
}

func detectByExtension(name string) (ArtifactClass, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".csv"):
		return ClassCSV, true
	case strings.HasSuffix(lower, ".json"):
		return ClassJSON, true
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		return ClassYAML, true
	case strings.HasSuffix(lower, ".pcap"), strings.HasSuffix(lower, ".cap"):
		return ClassPCAP, true
	case strings.HasSuffix(lower, ".pcapng"):
		return ClassPCAPNG, true
	}
	return "", false
}

func looksTextual(d []byte) bool {
	if len(d) == 0 {
		return false
	}
	limit := len(d)
	if limit > 512 {
		limit = 512
	}
	for _, b := range d[:limit] {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			if b != 0x1b { // allow ESC
				return false
			}
		}
	}
	return true
}
