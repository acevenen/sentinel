package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/acevenen/sentinel/internal/analyzer"
)

func TestDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Format != "terminal" || cfg.Severity != "low" || cfg.Concurrency != 4 || cfg.Model != DefaultModel {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadWithoutFileUsesDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != "terminal" || cfg.Concurrency != 4 {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestLoadYAMLOverlay(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	yaml := `
format: json
severity: high
concurrency: 8
model: custom-model
exclude:
  - "**/generated/**"
`
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != "json" || cfg.Severity != "high" || cfg.Concurrency != 8 || cfg.Model != "custom-model" {
		t.Errorf("yaml overlay not applied: %+v", cfg)
	}
	if len(cfg.Exclude) != 1 || cfg.Exclude[0] != "**/generated/**" {
		t.Errorf("exclude not parsed: %v", cfg.Exclude)
	}
}

func TestEnvBeatsYAML(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("format: json\nconcurrency: 8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SENTINEL_FORMAT", "sarif")
	t.Setenv("SENTINEL_CONCURRENCY", "2")
	t.Setenv("SENTINEL_INCLUDE", "*.go, *.py")
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != "sarif" {
		t.Errorf("env format not applied: %q", cfg.Format)
	}
	if cfg.Concurrency != 2 {
		t.Errorf("env concurrency not applied: %d", cfg.Concurrency)
	}
	if len(cfg.Include) != 2 || cfg.Include[0] != "*.go" || cfg.Include[1] != "*.py" {
		t.Errorf("env include not parsed: %v", cfg.Include)
	}
	if cfg.APIKey != "sk-test" {
		t.Errorf("api key not read from env")
	}
}

func TestInvalidYAMLIsAnError(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(":\t not yaml ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("want error for invalid yaml")
	}
}

func TestAPIKeyNotReadableFromYAML(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("apikey: leaked\napi_key: leaked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "" {
		t.Fatalf("API key must never come from yaml, got %q", cfg.APIKey)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid defaults", func(c *Config) {}, false},
		{"bad format", func(c *Config) { c.Format = "xml" }, true},
		{"bad severity", func(c *Config) { c.Severity = "extreme" }, true},
		{"zero concurrency", func(c *Config) { c.Concurrency = 0 }, true},
		{"negative concurrency", func(c *Config) { c.Concurrency = -2 }, true},
		{"empty model", func(c *Config) { c.Model = "  " }, true},
		{"all formats valid", func(c *Config) { c.Format = "sarif" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			if err := cfg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMinSeverity(t *testing.T) {
	cfg := Default()
	cfg.Severity = "HIGH"
	if got := cfg.MinSeverity(); got != analyzer.SeverityHigh {
		t.Errorf("MinSeverity = %q, want high", got)
	}
}

// clearEnv isolates tests from the developer's real environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"SENTINEL_FORMAT", "SENTINEL_SEVERITY", "SENTINEL_OUT", "SENTINEL_MODEL",
		"SENTINEL_CONCURRENCY", "SENTINEL_INCLUDE", "SENTINEL_EXCLUDE", "ANTHROPIC_API_KEY",
	} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}
