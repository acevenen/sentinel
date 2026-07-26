package metasploit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateResourceScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.rc")
	if err := os.WriteFile(path, []byte("set RHOSTS 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResource(path, "192.0.2.10"); err != nil {
		t.Fatalf("ValidateResource() error = %v", err)
	}
	if err := ValidateResource(path, "198.51.100.2"); err == nil {
		t.Fatal("ValidateResource() accepted a resource targeting another host")
	}
}
