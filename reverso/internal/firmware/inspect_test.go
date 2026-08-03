package firmware

import (
	"strings"
	"testing"

	"github.com/acevenen/sentinel/reverso/internal/confidence"
)

func TestInspectExtractsMetadata(t *testing.T) {
	body := "BusyBox v1.31.1 built-in shell\nOpenSSL 1.0.2u\nsome padding here\n" +
		"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n" +
		"telnetd -l /bin/login\n"
	r := Inspect("fw.bin", []byte(body))
	if r.StringCount == 0 {
		t.Fatal("expected extracted strings")
	}
	if len(r.SBOM) < 2 {
		t.Fatalf("expected busybox and openssl in SBOM, got %+v", r.SBOM)
	}
	foundTelnet := false
	for _, f := range r.Insecure {
		if f.ID == "telnet-service" {
			foundTelnet = true
		}
	}
	if !foundTelnet {
		t.Fatalf("expected telnet flag, got %+v", r.Insecure)
	}
	if len(r.KeyMarkers) != 1 || r.KeyMarkers[0].Kind != "certificate" {
		t.Fatalf("expected one certificate marker, got %+v", r.KeyMarkers)
	}
}

// Private key material is flagged but never extracted: the marker is redacted
// and no key bytes appear in the report.
func TestInspectRedactsPrivateKeys(t *testing.T) {
	secret := "SUPERSECRETKEYBYTES1234567890"
	body := "-----BEGIN RSA PRIVATE KEY-----\n" + secret + "\n-----END RSA PRIVATE KEY-----\n"
	r := Inspect("fw.bin", []byte(body))
	if len(r.KeyMarkers) != 1 {
		t.Fatalf("expected one private-key marker, got %+v", r.KeyMarkers)
	}
	km := r.KeyMarkers[0]
	if !km.IsPrivate || !km.Redacted {
		t.Fatalf("private key marker not redacted: %+v", km)
	}
	// The report's findings must not contain the secret bytes.
	for _, f := range Findings(r, "sha256:deadbeef") {
		for _, o := range append(append([]string{}, f.Observation...), f.Inference...) {
			if strings.Contains(o, secret) {
				t.Fatalf("finding leaked private key material: %q", o)
			}
		}
		// Private-key findings must state prohibited next steps.
		if f.Classification == "key-management" && len(f.ProhibitedNextSteps) == 0 {
			t.Fatal("key-management finding must list prohibited next steps")
		}
	}
}

func TestFindingsAreValid(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\ntelnetd\n"
	r := Inspect("fw.bin", []byte(body))
	fs := Findings(r, "sha256:abcd1234")
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			t.Fatalf("finding %s invalid: %v", f.ID, err)
		}
	}
}

func TestEntropyOfRandomIsHigh(t *testing.T) {
	// Incrementing bytes give a flat distribution -> entropy near 8 bits.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	r := Inspect("x", data)
	if r.Entropy < 7.9 {
		t.Fatalf("entropy = %f, want ~8", r.Entropy)
	}
}

var _ = confidence.Low
