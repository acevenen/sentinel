// Package protocol performs passive analysis of owner-provided captures. It
// reads capture files only; it never transmits. The classic-pcap summary here
// is the Milestone-1 foundation; message clustering and field inference are
// Milestone-2 work that builds on these parsed records.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrNotPCAP means the bytes are not a classic libpcap capture.
var ErrNotPCAP = errors.New("not a classic pcap capture")

// ErrTruncated means a record header ran past the end of the file.
var ErrTruncated = errors.New("capture is truncated")

// Summary is the passive summary of a capture.
type Summary struct {
	LinkType    uint32        `json:"link_type"`
	Packets     int           `json:"packets"`
	TotalBytes  uint64        `json:"total_bytes"`
	FirstTime   time.Time     `json:"first_time"`
	LastTime    time.Time     `json:"last_time"`
	Duration    time.Duration `json:"duration"`
	SnapLen     uint32        `json:"snap_len"`
	ByteOrder   string        `json:"byte_order"`
	Nanoseconds bool          `json:"nanoseconds"`
}

const (
	pcapMagicMicros = 0xa1b2c3d4
	pcapMagicNanos  = 0xa1b23c4d
)

// SummarizePCAP parses a classic libpcap file into a passive Summary. It never
// interprets packet payloads beyond counting bytes, keeping this strictly
// observational.
func SummarizePCAP(data []byte) (Summary, error) {
	if len(data) < 24 {
		return Summary{}, ErrNotPCAP
	}
	var (
		bo    binary.ByteOrder
		nanos bool
	)
	magicBE := binary.BigEndian.Uint32(data[:4])
	magicLE := binary.LittleEndian.Uint32(data[:4])
	switch {
	case magicLE == pcapMagicMicros:
		bo = binary.LittleEndian
	case magicLE == pcapMagicNanos:
		bo, nanos = binary.LittleEndian, true
	case magicBE == pcapMagicMicros:
		bo = binary.BigEndian
	case magicBE == pcapMagicNanos:
		bo, nanos = binary.BigEndian, true
	default:
		return Summary{}, ErrNotPCAP
	}

	s := Summary{
		SnapLen:     bo.Uint32(data[16:20]),
		LinkType:    bo.Uint32(data[20:24]),
		Nanoseconds: nanos,
	}
	if bo == binary.BigEndian {
		s.ByteOrder = "big"
	} else {
		s.ByteOrder = "little"
	}

	// int64 arithmetic keeps offset math correct even where int is 32-bit and a
	// crafted 32-bit inclLen would otherwise overflow the bounds check.
	off := int64(24)
	total := int64(len(data))
	for off+16 <= total {
		tsSec := bo.Uint32(data[off : off+4])
		tsFrac := bo.Uint32(data[off+4 : off+8])
		inclLen := int64(bo.Uint32(data[off+8 : off+12]))
		off += 16
		if off+inclLen > total {
			return s, fmt.Errorf("%w: packet %d claims %d bytes", ErrTruncated, s.Packets+1, inclLen)
		}
		var frac int64
		if nanos {
			frac = int64(tsFrac)
		} else {
			frac = int64(tsFrac) * 1000
		}
		ts := time.Unix(int64(tsSec), frac).UTC()
		if s.Packets == 0 {
			s.FirstTime = ts
		}
		s.LastTime = ts
		s.TotalBytes += uint64(inclLen)
		s.Packets++
		off += inclLen
	}
	if !s.FirstTime.IsZero() {
		s.Duration = s.LastTime.Sub(s.FirstTime)
	}
	return s, nil
}
