// Package firmware extracts defensive metadata from owner-supplied firmware
// images: format, entropy, a strings inventory, a lightweight software bill of
// materials, and flags for insecure configurations. It records where key and
// certificate material is *referenced* without ever extracting private
// material, and it never emits bypass instructions.
package firmware

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/acevenen/sentinel/reverso/internal/confidence"
	"github.com/acevenen/sentinel/reverso/internal/ingest"
)

// KeyMarker records the presence of key or certificate material at an offset.
// For private material it records only the fact and location, never the bytes.
type KeyMarker struct {
	Kind      string `json:"kind"` // e.g. "certificate", "private_key"
	Offset    int    `json:"offset"`
	IsPrivate bool   `json:"is_private"`
	Redacted  bool   `json:"redacted"`
}

// Component is one entry in the software bill of materials.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// InsecureFlag is a defensively-worded configuration concern.
type InsecureFlag struct {
	ID       string `json:"id"`
	Evidence string `json:"evidence"`
}

// Report is the structured result of inspecting a firmware image.
type Report struct {
	OriginalName string         `json:"original_name"`
	Class        string         `json:"class"`
	SizeBytes    int            `json:"size_bytes"`
	Entropy      float64        `json:"entropy"`
	StringCount  int            `json:"string_count"`
	TopStrings   []string       `json:"top_strings"`
	KeyMarkers   []KeyMarker    `json:"key_markers"`
	SBOM         []Component    `json:"sbom"`
	Insecure     []InsecureFlag `json:"insecure_flags"`
}

var (
	stringRe = regexp.MustCompile(`[\x20-\x7e]{4,}`)
	sbomRes  = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"busybox", regexp.MustCompile(`(?i)busybox v?(\d+\.\d+\.\d+)`)},
		{"openssl", regexp.MustCompile(`(?i)openssl (\d+\.\d+\.\d+[a-z]?)`)},
		{"dropbear", regexp.MustCompile(`(?i)dropbear[ _]v?(\d+\.\d+)`)},
		{"lighttpd", regexp.MustCompile(`(?i)lighttpd[ /](\d+\.\d+\.\d+)`)},
		{"linux", regexp.MustCompile(`(?i)linux version (\d+\.\d+\.\d+)`)},
		{"u-boot", regexp.MustCompile(`(?i)u-boot (\d{4}\.\d{2})`)},
	}
)

// Inspect produces a defensive metadata report for a firmware image.
func Inspect(name string, data []byte) Report {
	det := ingest.Detect(name, data)
	r := Report{
		OriginalName: name,
		Class:        string(det.Class),
		SizeBytes:    len(data),
		Entropy:      shannonEntropy(data),
	}
	strs := extractStrings(data)
	r.StringCount = len(strs)
	r.TopStrings = topN(strs, 25)
	r.KeyMarkers = findKeyMarkers(data)
	r.SBOM = buildSBOM(strs)
	r.Insecure = flagInsecure(strs)
	return r
}

// Findings converts a report to confidence-model findings for a project,
// keeping observation separate from inference and stating prohibited next
// steps explicitly.
func Findings(r Report, evidenceID string) []confidence.Finding {
	var out []confidence.Finding
	for _, km := range r.KeyMarkers {
		if !km.IsPrivate {
			continue
		}
		out = append(out, confidence.Finding{
			ID:             "REV-KEY-" + evidenceIDShort(evidenceID),
			Title:          "Private key material appears embedded in the image",
			Classification: "key-management",
			Observation:    []string{"a private-key PEM header is present in the image at offset " + itoa(km.Offset)},
			Inference:      []string{"the device may ship with a static private key, which weakens per-device trust"},
			Confidence:     confidence.Medium,
			EvidenceIDs:    []string{evidenceID},
			Alternatives:   []string{"the region may be an unused template or test key", "the header may be a false positive inside compressed data"},
			NextSafeTest:   []string{"compare this region across two firmware versions in the differential module", "confirm the surrounding structure with a passive format parse"},
			ProhibitedNextSteps: []string{
				"extracting or reconstructing the private key",
				"using the key to sign or impersonate the device",
			},
		})
	}
	for _, f := range r.Insecure {
		out = append(out, confidence.Finding{
			ID:             "REV-CFG-" + f.ID,
			Title:          "Potentially insecure default configuration observed",
			Classification: "configuration",
			Observation:    []string{f.Evidence},
			Inference:      []string{"the default configuration may expose an unnecessary service or weak credential policy"},
			Confidence:     confidence.Low,
			EvidenceIDs:    []string{evidenceID},
			NextSafeTest:   []string{"review the referenced configuration file in a mounted read-only copy of the filesystem"},
			ProhibitedNextSteps: []string{
				"connecting to or authenticating against any live service",
			},
		})
	}
	return out
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	entropy := 0.0
	n := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func extractStrings(data []byte) []string {
	return stringRe.FindAllString(string(data), -1)
}

func topN(strs []string, n int) []string {
	freq := map[string]int{}
	for _, s := range strs {
		freq[s]++
	}
	uniq := make([]string, 0, len(freq))
	for s := range freq {
		uniq = append(uniq, s)
	}
	sort.Slice(uniq, func(i, j int) bool {
		if freq[uniq[i]] != freq[uniq[j]] {
			return freq[uniq[i]] > freq[uniq[j]]
		}
		return uniq[i] < uniq[j]
	})
	if len(uniq) > n {
		uniq = uniq[:n]
	}
	return uniq
}

var keyHeaders = []struct {
	marker    string
	kind      string
	isPrivate bool
}{
	{"-----BEGIN CERTIFICATE-----", "certificate", false},
	{"-----BEGIN PUBLIC KEY-----", "public_key", false},
	{"-----BEGIN RSA PRIVATE KEY-----", "private_key", true},
	{"-----BEGIN EC PRIVATE KEY-----", "private_key", true},
	{"-----BEGIN PRIVATE KEY-----", "private_key", true},
	{"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key", true},
}

func findKeyMarkers(data []byte) []KeyMarker {
	s := string(data)
	var out []KeyMarker
	for _, h := range keyHeaders {
		from := 0
		for {
			idx := strings.Index(s[from:], h.marker)
			if idx < 0 {
				break
			}
			out = append(out, KeyMarker{
				Kind: h.kind, Offset: from + idx, IsPrivate: h.isPrivate, Redacted: h.isPrivate,
			})
			from += idx + len(h.marker)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

func buildSBOM(strs []string) []Component {
	seen := map[string]Component{}
	joined := strings.Join(strs, "\n")
	for _, s := range sbomRes {
		if m := s.re.FindStringSubmatch(joined); m != nil {
			ver := ""
			if len(m) > 1 {
				ver = m[1]
			}
			seen[s.name] = Component{Name: s.name, Version: ver}
		}
	}
	out := make([]Component, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func flagInsecure(strs []string) []InsecureFlag {
	var out []InsecureFlag
	joined := strings.Join(strs, "\n")
	if strings.Contains(joined, "telnetd") {
		out = append(out, InsecureFlag{ID: "telnet-service", Evidence: "a telnet daemon reference (telnetd) is present"})
	}
	// A root entry with an empty password field in a passwd-style line.
	if regexp.MustCompile(`(?m)^root::`).MatchString(joined) {
		out = append(out, InsecureFlag{ID: "empty-root-password", Evidence: "a passwd-style line shows root with an empty password field"})
	}
	if strings.Contains(joined, "PermitRootLogin yes") {
		out = append(out, InsecureFlag{ID: "ssh-permit-root", Evidence: "an sshd config permits direct root login"})
	}
	return out
}

func evidenceIDShort(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
