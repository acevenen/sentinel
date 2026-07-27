package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/tools"
	"github.com/acevenen/sentinel/internal/tools/aircrack"
	"github.com/acevenen/sentinel/internal/tools/hashcat"
	"github.com/acevenen/sentinel/internal/tools/hping"
	"github.com/acevenen/sentinel/internal/tools/kali"
	"github.com/acevenen/sentinel/internal/tools/metasploit"
	"github.com/acevenen/sentinel/internal/tools/setoolkit"
	"github.com/acevenen/sentinel/internal/tools/skipfish"
	"github.com/acevenen/sentinel/internal/tools/sqlmap"
	"github.com/acevenen/sentinel/internal/tools/tshark"
)

// Adapter output parsers consume tool stdout, which the safety model treats as
// untrusted target content ("Captured target content is scanned before it can
// influence the orchestrator"). The golden-file tests cover the happy path;
// these tests cover the adversarial path: malformed, hostile, and empty input
// must never panic, must fail closed on structurally invalid data, must not
// invent findings from noise, and must never leak recovered secrets.

// parser is the uniform signature every adapter parser is adapted to for the
// no-panic sweep. Non-erroring parsers are wrapped to return a nil error.
type parser func([]byte) ([]tools.Finding, error)

// allParsers returns every untrusted-output parser under a stable name.
func allParsers() map[string]parser {
	return map[string]parser{
		"sqlmap":      func(b []byte) ([]tools.Finding, error) { return sqlmap.ParseOutput(b, "https://lab.local/x?id=1"), nil },
		"aircrack-ng": func(b []byte) ([]tools.Finding, error) { return aircrack.ParseOutput(b, "AA:BB:CC:DD:EE:FF"), nil },
		"hping3":      func(b []byte) ([]tools.Finding, error) { return hping.ParseOutput(b), nil },
		"kali-utils":  func(b []byte) ([]tools.Finding, error) { return kali.ParseOutput(b, "https://lab.local"), nil },
		"skipfish":    func(b []byte) ([]tools.Finding, error) { return skipfish.ParseSummary(b), nil },
		"hashcat":     func(b []byte) ([]tools.Finding, error) { return hashcat.ParseShow(b), nil },
		"metasploit":  func(b []byte) ([]tools.Finding, error) { return metasploit.ParseOutput(b, "192.0.2.10"), nil },
		"tshark":      tshark.ParseJSON,
		"set":         setoolkit.ParseResults,
	}
}

// hostileInputs is the battery of malformed and abusive byte streams every
// parser must survive without panicking.
func hostileInputs() map[string][]byte {
	return map[string][]byte{
		"empty":              {},
		"only-newlines":      []byte("\n\n\n\r\n"),
		"nul-and-control":    []byte("\x00\x01\x02line\x00with\x1bcontrol\x7f\n"),
		"invalid-utf8":       {0xff, 0xfe, 0xfd, '\n', 0xc3, 0x28},
		"long-single-line":   []byte(strings.Repeat("A", 1<<20)),
		"many-empty-fields":  []byte(strings.Repeat(":\n", 5000)),
		"unterminated-json":  []byte(`[{"_source":{"layers":{"ip":{`),
		"unterminated-quote": []byte("Parameter: \"id (GET)\nType: boolean"),
		"delimiters-only":    []byte("|||\n[]\n()\n,,,\n::\n"),
		"crlf-mixed":         []byte("len=1\rip=x\r\nParameter: p (GET)\r\n"),
	}
}

func TestParsersSurviveHostileInputWithoutPanicking(t *testing.T) {
	for name, parse := range allParsers() {
		for inputName, data := range hostileInputs() {
			t.Run(name+"/"+inputName, func(t *testing.T) {
				// A panic here fails the test automatically; an error is a
				// legitimate fail-closed result, not a failure of the test.
				if _, err := parse(data); err != nil {
					t.Logf("%s rejected %s input: %v", name, inputName, err)
				}
			})
		}
	}
}

func TestStructuredParsersFailClosedOnMalformedInput(t *testing.T) {
	t.Run("tshark rejects non-JSON", func(t *testing.T) {
		findings, err := tshark.ParseJSON([]byte("{ this is not valid json"))
		if err == nil {
			t.Fatal("ParseJSON accepted malformed JSON; structured parsers must fail closed")
		}
		if findings != nil {
			t.Fatalf("ParseJSON returned findings alongside an error: %#v", findings)
		}
	})

	t.Run("setoolkit rejects a non-numeric count", func(t *testing.T) {
		findings, err := setoolkit.ParseResults([]byte("clicks,notanumber\n"))
		if err == nil {
			t.Fatal("ParseResults accepted a non-numeric count; it must fail closed")
		}
		if findings != nil {
			t.Fatalf("ParseResults returned findings alongside an error: %#v", findings)
		}
	})

	t.Run("setoolkit rejects ragged rows with a bad count", func(t *testing.T) {
		// csv.Reader rejects a row whose field count differs from the first
		// row; a wrong-arity record must surface as an error, not silent data.
		if _, err := setoolkit.ParseResults([]byte("metric,count\nclicks,3,extra\n")); err == nil {
			t.Fatal("ParseResults accepted a ragged CSV row")
		}
	})
}

func TestParsersReturnNoFindingsForNoiseWithoutConfirmationMarkers(t *testing.T) {
	cases := []struct {
		name  string
		parse parser
		noise string
	}{
		{"sqlmap", allParsers()["sqlmap"], "[INFO] testing connection to the target URL\n[WARNING] no parameter found\n"},
		{"aircrack-ng", allParsers()["aircrack-ng"], "CH  6 ][ Elapsed: 12 s ][ 2026-07-27 21:00\nBSSID              PWR  Beacons\n"},
		{"hping3", allParsers()["hping3"], "HPING 192.0.2.10 (eth0 192.0.2.10): S set, 40 headers + 0 data bytes\n"},
		{"kali-utils", allParsers()["kali-utils"], "starting fingerprint run\nno technologies identified\n"},
		{"skipfish", allParsers()["skipfish"], "scan complete, 0 issues sampled\n---\n"},
		{"hashcat", allParsers()["hashcat"], "Session..........: hashcat\nStatus...........: Exhausted\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, err := c.parse([]byte(c.noise))
			if err != nil {
				t.Fatalf("unexpected error on benign noise: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("parser invented %d finding(s) from noise: %#v", len(findings), findings)
			}
		})
	}
}

// TestRecoveredSecretsAreRedactedFromFindings guards the core promise of the
// credential-handling adapters: recovered plaintext, keys, and captured
// authentication material are redacted from Sentinel output and never appear
// in a Finding. A regression here would leak secrets into reports and the
// audit log.
func TestRecoveredSecretsAreRedactedFromFindings(t *testing.T) {
	const secret = "S3cr3t-Do-Not-Leak-8f2a"

	t.Run("hashcat redacts recovered plaintext", func(t *testing.T) {
		out := "d41d8cd98f00b204e9800998ecf8427e:" + secret + "\n"
		findings := hashcat.ParseShow([]byte(out))
		if len(findings) != 1 {
			t.Fatalf("expected one cracked-hash finding, got %d", len(findings))
		}
		assertSecretAbsent(t, secret, findings)
	})

	t.Run("aircrack redacts recovered key material", func(t *testing.T) {
		out := "WPA (1 handshake)\nKEY FOUND! [ " + secret + " ]\n"
		findings := aircrack.ParseOutput([]byte(out), "AA:BB:CC:DD:EE:FF")
		if len(findings) != 2 {
			t.Fatalf("expected handshake and key findings, got %d: %#v", len(findings), findings)
		}
		assertSecretAbsent(t, secret, findings)
	})

	t.Run("tshark redacts captured credential fields", func(t *testing.T) {
		capture := `[{"_source":{"layers":{` +
			`"ip":{"ip.src":"192.0.2.5","ip.dst":"192.0.2.9"},` +
			`"http":{"http.authorization":"Basic ` + secret + `"}}}}]`
		findings, err := tshark.ParseJSON([]byte(capture))
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) == 0 {
			t.Fatal("expected at least a credential-exposure finding")
		}
		var sawCredential bool
		for _, f := range findings {
			if f.Severity == "high" {
				sawCredential = true
			}
		}
		if !sawCredential {
			t.Fatalf("expected a high-severity credential-exposure finding: %#v", findings)
		}
		assertSecretAbsent(t, secret, findings)
	})
}

// assertSecretAbsent fails if the secret appears anywhere in the fully
// marshaled findings — id, title, description, evidence, target, or metadata.
func assertSecretAbsent(t *testing.T, secret string, findings []tools.Finding) {
	t.Helper()
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("recovered secret leaked into findings: %s", encoded)
	}
}
