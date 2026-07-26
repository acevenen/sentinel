// Package config resolves Sentinel settings with the precedence
// flags > environment > .sentinel.yaml > defaults. The API key is read from
// ANTHROPIC_API_KEY only and is never written to disk.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/report"
)

// FileName is the optional per-repository config file.
const FileName = ".sentinel.yaml"

const (
	defaultEngagementDir = ".sentinel-data/engagements"
	defaultAuditLog      = ".sentinel-data/audit.jsonl"
	defaultStateDir      = ".sentinel-data/state"
)

// DefaultModel is the model used when none is configured.
const DefaultModel = "claude-sonnet-4-5"

// Config holds every tunable setting for a scan.
type Config struct {
	Format      string   `yaml:"format"`
	Severity    string   `yaml:"severity"`
	Out         string   `yaml:"out"`
	Include     []string `yaml:"include"`
	Exclude     []string `yaml:"exclude"`
	Concurrency int      `yaml:"concurrency"`
	Model       string   `yaml:"model"`

	// APIKey comes from the ANTHROPIC_API_KEY environment variable only;
	// it is deliberately not readable from the YAML file.
	APIKey string `yaml:"-"`
}

// Default returns the baseline configuration.
func Default() Config {
	return Config{
		Format:      report.FormatTerminal,
		Severity:    string(analyzer.SeverityLow),
		Concurrency: 4,
		Model:       DefaultModel,
	}
}

// Load resolves configuration for a scan rooted at dir:
// defaults, overlaid by dir/.sentinel.yaml (if present), overlaid by env vars.
func Load(dir string) (Config, error) {
	cfg := Default()

	path := filepath.Join(dir, FileName)
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	cfg.applyEnv()
	return cfg, nil
}

// applyEnv overlays SENTINEL_* variables and reads the API key.
func (c *Config) applyEnv() {
	if v := os.Getenv("SENTINEL_FORMAT"); v != "" {
		c.Format = v
	}
	if v := os.Getenv("SENTINEL_SEVERITY"); v != "" {
		c.Severity = v
	}
	if v := os.Getenv("SENTINEL_OUT"); v != "" {
		c.Out = v
	}
	if v := os.Getenv("SENTINEL_MODEL"); v != "" {
		c.Model = v
	}
	if v := os.Getenv("SENTINEL_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Concurrency = n
		}
	}
	if v := os.Getenv("SENTINEL_INCLUDE"); v != "" {
		c.Include = splitList(v)
	}
	if v := os.Getenv("SENTINEL_EXCLUDE"); v != "" {
		c.Exclude = splitList(v)
	}
	c.APIKey = os.Getenv("ANTHROPIC_API_KEY")
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate rejects impossible settings before a scan starts.
func (c *Config) Validate() error {
	valid := false
	for _, f := range report.Formats {
		if c.Format == f {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid format %q (want one of %v)", c.Format, report.Formats)
	}
	if _, ok := analyzer.ParseSeverity(c.Severity); !ok {
		return fmt.Errorf("invalid severity %q (want one of %v)", c.Severity, analyzer.Severities)
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1, got %d", c.Concurrency)
	}
	if strings.TrimSpace(c.Model) == "" {
		return fmt.Errorf("model must not be empty")
	}
	return nil
}

// MinSeverity returns the parsed severity threshold.
func (c *Config) MinSeverity() analyzer.Severity {
	sev, _ := analyzer.ParseSeverity(c.Severity)
	return sev
}

// OperationalConfig contains local platform paths and global safety controls.
// It is separate from scan configuration so existing scan precedence and
// validation remain backwards compatible.
type OperationalConfig struct {
	EngagementDir string
	AuditLog      string
	StateDir      string
	KillSwitch    bool
}

// LoadOperational reads environment-only operational settings. Engagement
// records themselves carry scope, rate, and concurrency policy.
func LoadOperational() OperationalConfig {
	cfg := OperationalConfig{
		EngagementDir: defaultEngagementDir,
		AuditLog:      defaultAuditLog,
		StateDir:      defaultStateDir,
	}
	if value := strings.TrimSpace(os.Getenv("SENTINEL_ENGAGEMENT_DIR")); value != "" {
		cfg.EngagementDir = value
	}
	if value := strings.TrimSpace(os.Getenv("SENTINEL_AUDIT_LOG")); value != "" {
		cfg.AuditLog = value
	}
	if value := strings.TrimSpace(os.Getenv("SENTINEL_STATE_DIR")); value != "" {
		cfg.StateDir = value
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SENTINEL_KILL_SWITCH"))) {
	case "1", "true", "yes", "on", "stop":
		cfg.KillSwitch = true
	}
	return cfg
}
