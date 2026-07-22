// Package hunt implements sentinel's authorized IDOR/BOLA testing for bug
// bounty work. It is scope-first: every request is checked against a declared
// program scope before it is ever sent, it uses the researcher's own test
// accounts (tokens read from the environment, never stored), and it is
// read-only — it proves a broken-object-level-authorization leak without
// mutating the target's data.
//
// This is authorization testing, the same theme as guard/evaluate: guard asks
// whether an agent exceeds its authority; hunt asks whether an API enforces
// object-level authority at all.
package hunt

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Program is a bug-bounty program's declared scope, the researcher's test
// identities, and the request templates to probe. It is the single source of
// authorization: nothing outside this scope is ever contacted.
type Program struct {
	Name       string   `yaml:"name"`
	Platform   string   `yaml:"platform"`
	BaseURL    string   `yaml:"base_url"`
	InScope    []string `yaml:"in_scope"`
	OutOfScope []string `yaml:"out_of_scope"`
	// RateLimitRPS caps outbound requests per second (politeness / anti-DoS).
	// Zero means use the conservative default.
	RateLimitRPS float64           `yaml:"rate_limit_rps"`
	Identities   []Identity        `yaml:"identities"`
	Requests     []RequestTemplate `yaml:"requests"`
}

// Identity is one test account the researcher legitimately controls. The token
// is read from TokenEnv at runtime and never persisted to the manifest or logs.
type Identity struct {
	Name     string `yaml:"name"`
	Header   string `yaml:"header"`    // e.g. "Authorization"
	Prefix   string `yaml:"prefix"`    // e.g. "Bearer " (optional)
	TokenEnv string `yaml:"token_env"` // env var holding the session token
}

// RequestTemplate is an endpoint that takes an object identifier, plus the
// object IDs each identity legitimately owns. The cross-account test replays
// one identity's owned objects using another identity's session.
type RequestTemplate struct {
	ID     string `yaml:"id"`
	Method string `yaml:"method"` // GET or HEAD only (read-only)
	// Path is joined to BaseURL, or used as-is if it is an absolute URL. It must
	// contain the "{id}" placeholder.
	Path string `yaml:"path"`
	// Owned maps an identity name to the object IDs it legitimately owns.
	Owned map[string][]string `yaml:"owned"`
	// SuccessStatus is the HTTP status a legitimate owner receives (default 200).
	SuccessStatus int `yaml:"success_status"`
}

// idPlaceholder is the token replaced with an object ID in a template path.
const idPlaceholder = "{id}"

// DefaultRateLimitRPS is used when a program declares no rate limit.
const DefaultRateLimitRPS = 2.0

// Status returns the template's success status, defaulting to 200.
func (r RequestTemplate) Status() int {
	if r.SuccessStatus == 0 {
		return 200
	}
	return r.SuccessStatus
}

// readOnlyMethod reports whether a method only reads state. Hunt refuses
// anything else so it never mutates the target's data.
func readOnlyMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "":
		return true
	default:
		return false
	}
}

// LoadProgram reads and validates a program manifest from a YAML file.
func LoadProgram(path string) (Program, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Program{}, fmt.Errorf("reading program file: %w", err)
	}
	var p Program
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Program{}, fmt.Errorf("parsing program file %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return Program{}, err
	}
	return p, nil
}

// Validate rejects a program that is unsafe or too underspecified to run. It is
// deliberately strict: a bad scope config must fail loudly, not silently send
// requests somewhere unintended.
func (p Program) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("program.name is required")
	}
	if strings.TrimSpace(p.BaseURL) == "" {
		return fmt.Errorf("program.base_url is required")
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("program.base_url %q is not a valid absolute URL", p.BaseURL)
	}
	if len(p.InScope) == 0 {
		return fmt.Errorf("program.in_scope must list at least one host (scope is mandatory)")
	}
	if len(p.Identities) < 2 {
		return fmt.Errorf("program needs at least two test identities (an attacker and a victim) to test object-level authorization")
	}

	seen := map[string]bool{}
	for _, id := range p.Identities {
		if strings.TrimSpace(id.Name) == "" {
			return fmt.Errorf("every identity needs a name")
		}
		if seen[id.Name] {
			return fmt.Errorf("duplicate identity name %q", id.Name)
		}
		seen[id.Name] = true
		if strings.TrimSpace(id.Header) == "" || strings.TrimSpace(id.TokenEnv) == "" {
			return fmt.Errorf("identity %q needs both a header and a token_env", id.Name)
		}
	}

	if len(p.Requests) == 0 {
		return fmt.Errorf("program lists no request templates to test")
	}
	for _, r := range p.Requests {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("every request template needs an id")
		}
		if !strings.Contains(r.Path, idPlaceholder) {
			return fmt.Errorf("request %q path must contain the %s placeholder", r.ID, idPlaceholder)
		}
		if !readOnlyMethod(r.Method) {
			return fmt.Errorf("request %q uses method %q; hunt is read-only (GET/HEAD) so it never mutates target data", r.ID, r.Method)
		}
		if len(r.Owned) == 0 {
			return fmt.Errorf("request %q must declare which object IDs each identity owns", r.ID)
		}
		for name := range r.Owned {
			if !seen[name] {
				return fmt.Errorf("request %q references unknown identity %q", r.ID, name)
			}
		}
	}
	return nil
}
