// Package binmap performs defensive, read-only analysis of ELF binaries. It
// inventories sections and symbols and locates likely cryptographic and trust-
// decision functions so a reviewer can find where verification happens. It
// never patches, disables, or rewrites verification logic.
package binmap

import (
	"bytes"
	"debug/elf"
	"fmt"
	"regexp"
	"sort"
)

// Report is the defensive summary of an ELF binary.
type Report struct {
	Class         string   `json:"class"`
	Machine       string   `json:"machine"`
	Type          string   `json:"type"`
	Entry         uint64   `json:"entry"`
	Sections      []string `json:"sections"`
	SymbolCount   int      `json:"symbol_count"`
	ImportedCount int      `json:"imported_count"`
	CryptoSymbols []string `json:"crypto_symbols"`
	TrustSymbols  []string `json:"trust_symbols"`
	ParserSymbols []string `json:"parser_symbols"`
	Stripped      bool     `json:"stripped"`
}

var (
	cryptoRe = regexp.MustCompile(`(?i)(aes|des|rsa|ecdsa|ecdh|sha1|sha256|sha512|md5|hmac|evp_|chacha|poly1305|crypt|cipher)`)
	trustRe  = regexp.MustCompile(`(?i)(verify|validate|authent|signature|sign_check|secure_boot|attest|check_sig|is_valid|permission|authoriz)`)
	parserRe = regexp.MustCompile(`(?i)(parse|decode|unmarshal|deserialize|scan_|read_header|tlv_)`)
)

// Analyze parses ELF bytes into a defensive report.
func Analyze(data []byte) (Report, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return Report{}, fmt.Errorf("parsing ELF: %w", err)
	}
	defer func() { _ = f.Close() }()

	r := Report{
		Class:   f.Class.String(),
		Machine: f.Machine.String(),
		Type:    f.Type.String(),
		Entry:   f.Entry,
	}
	for _, s := range f.Sections {
		r.Sections = append(r.Sections, s.Name)
	}

	syms, err := f.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		return Report{}, fmt.Errorf("reading symbols: %w", err)
	}
	imported, _ := f.ImportedSymbols()
	r.ImportedCount = len(imported)
	r.Stripped = len(syms) == 0

	cryptoSet := map[string]struct{}{}
	trustSet := map[string]struct{}{}
	parserSet := map[string]struct{}{}
	consider := func(name string) {
		if name == "" {
			return
		}
		if cryptoRe.MatchString(name) {
			cryptoSet[name] = struct{}{}
		}
		if trustRe.MatchString(name) {
			trustSet[name] = struct{}{}
		}
		if parserRe.MatchString(name) {
			parserSet[name] = struct{}{}
		}
	}
	for _, s := range syms {
		consider(s.Name)
	}
	r.SymbolCount = len(syms)
	for _, s := range imported {
		consider(s.Name)
	}

	r.CryptoSymbols = sortedKeys(cryptoSet)
	r.TrustSymbols = sortedKeys(trustSet)
	r.ParserSymbols = sortedKeys(parserSet)
	return r, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
