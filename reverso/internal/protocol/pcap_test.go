package protocol

import (
	"encoding/binary"
	"errors"
	"testing"
)

// buildPCAP creates a tiny little-endian microsecond capture with the given
// packet payload sizes.
func buildPCAP(linkType uint32, sizes []int) []byte {
	buf := make([]byte, 24)
	bo := binary.LittleEndian
	bo.PutUint32(buf[0:4], pcapMagicMicros)
	bo.PutUint16(buf[4:6], 2)
	bo.PutUint16(buf[6:8], 4)
	bo.PutUint32(buf[16:20], 65535)
	bo.PutUint32(buf[20:24], linkType)
	ts := uint32(1000)
	for _, n := range sizes {
		hdr := make([]byte, 16)
		bo.PutUint32(hdr[0:4], ts)
		bo.PutUint32(hdr[4:8], 0)
		bo.PutUint32(hdr[8:12], uint32(n))
		bo.PutUint32(hdr[12:16], uint32(n))
		buf = append(buf, hdr...)
		buf = append(buf, make([]byte, n)...)
		ts += 2
	}
	return buf
}

func TestSummarizePCAP(t *testing.T) {
	data := buildPCAP(1, []int{10, 20, 30})
	s, err := SummarizePCAP(data)
	if err != nil {
		t.Fatalf("SummarizePCAP: %v", err)
	}
	if s.Packets != 3 {
		t.Fatalf("packets = %d, want 3", s.Packets)
	}
	if s.TotalBytes != 60 {
		t.Fatalf("bytes = %d, want 60", s.TotalBytes)
	}
	if s.LinkType != 1 {
		t.Fatalf("link type = %d, want 1", s.LinkType)
	}
	if s.ByteOrder != "little" {
		t.Fatalf("byte order = %s", s.ByteOrder)
	}
}

func TestSummarizePCAPRejectsNonPCAP(t *testing.T) {
	if _, err := SummarizePCAP([]byte("not a pcap file at all!!")); !errors.Is(err, ErrNotPCAP) {
		t.Fatalf("error = %v, want ErrNotPCAP", err)
	}
}

func TestSummarizePCAPDetectsTruncation(t *testing.T) {
	data := buildPCAP(1, []int{10})
	data = data[:len(data)-5] // chop off part of the payload
	if _, err := SummarizePCAP(data); !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
}
