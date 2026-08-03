package binmap

import (
	"testing"
)

func TestAnalyzeRejectsNonELF(t *testing.T) {
	if _, err := Analyze([]byte("this is not an elf binary")); err == nil {
		t.Fatal("Analyze accepted non-ELF data")
	}
}

// The regexes are the classification logic; pin them so a refactor cannot
// silently stop flagging trust and crypto functions.
func TestClassificationRegexes(t *testing.T) {
	crypto := []string{"AES_encrypt", "EVP_DigestVerify", "sha256_init", "hmac_update"}
	for _, n := range crypto {
		if !cryptoRe.MatchString(n) {
			t.Errorf("cryptoRe should match %q", n)
		}
	}
	trust := []string{"verify_signature", "secure_boot_check", "authenticate_user", "is_valid_token"}
	for _, n := range trust {
		if !trustRe.MatchString(n) {
			t.Errorf("trustRe should match %q", n)
		}
	}
	parsers := []string{"parse_header", "decode_frame", "tlv_read"}
	for _, n := range parsers {
		if !parserRe.MatchString(n) {
			t.Errorf("parserRe should match %q", n)
		}
	}
	benign := []string{"main", "printf", "helper_loop"}
	for _, n := range benign {
		if cryptoRe.MatchString(n) || trustRe.MatchString(n) {
			t.Errorf("no rule should match benign %q", n)
		}
	}
}
