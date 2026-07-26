// Package bounty imports operator-supplied program policy into Sentinel's
// normal engagement and authorization model.
package bounty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/engagement"
)

// Automation captures program-specific scanning limits.
type Automation struct {
	Allowed        bool    `json:"allowed" yaml:"allowed"`
	MaxRequestsRPS float64 `json:"max_requests_per_second" yaml:"max_requests_per_second"`
	MaxConcurrency int     `json:"max_concurrency" yaml:"max_concurrency"`
}

// HighRiskPermissions default false and require a separate written reference.
type HighRiskPermissions struct {
	Exploitation      bool `json:"exploitation" yaml:"exploitation"`
	SocialEngineering bool `json:"social_engineering" yaml:"social_engineering"`
}

// Program is a policy snapshot supplied by an enrolled researcher.
type Program struct {
	Name                          string              `json:"name" yaml:"name"`
	Platform                      string              `json:"platform" yaml:"platform"`
	PolicyURL                     string              `json:"policy_url" yaml:"policy_url"`
	Enrolled                      bool                `json:"enrolled" yaml:"enrolled"`
	Scope                         authz.Scope         `json:"scope" yaml:"scope"`
	Automation                    Automation          `json:"automation" yaml:"automation"`
	HighRisk                      HighRiskPermissions `json:"high_risk" yaml:"high_risk"`
	WrittenAuthorizationReference string              `json:"written_authorization_reference,omitempty" yaml:"written_authorization_reference,omitempty"`
}

// Load reads a strict, bounded program policy.
func Load(path string) (Program, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Program{}, fmt.Errorf("reading bounty program: %w", err)
	}
	if len(data) > 2<<20 {
		return Program{}, errors.New("bounty program exceeds 2 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var program Program
	if err := decoder.Decode(&program); err != nil {
		return Program{}, fmt.Errorf("decoding bounty program: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Program{}, errors.New("bounty program contains multiple documents")
		}
		return Program{}, err
	}
	if err := program.Validate(); err != nil {
		return Program{}, err
	}
	return program, nil
}

// Validate rejects ambiguous or unsafe policy snapshots.
func (p Program) Validate() error {
	if p.Name == "" || p.Platform == "" || !p.Enrolled || p.Scope.Empty() {
		return errors.New("bounty program requires name, platform, enrolled=true, and an allow-list")
	}
	parsed, err := url.Parse(p.PolicyURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("bounty program requires an absolute policy_url")
	}
	if p.Automation.MaxRequestsRPS < 0 || p.Automation.MaxConcurrency < 0 {
		return errors.New("bounty automation limits cannot be negative")
	}
	if p.Automation.Allowed && (p.Automation.MaxRequestsRPS <= 0 || p.Automation.MaxConcurrency <= 0) {
		return errors.New("allowed bounty automation requires positive rate and concurrency limits")
	}
	if (p.HighRisk.Exploitation || p.HighRisk.SocialEngineering) && p.WrittenAuthorizationReference == "" {
		return errors.New("high-risk bounty permissions require a written authorization reference")
	}
	return nil
}

// Engagement converts the program to the common deny-first authorization
// model after an explicit current-policy attestation.
func (p Program) Engagement(id, operator string, attested bool) (engagement.Record, error) {
	if !attested {
		return engagement.Record{}, errors.New("operator must attest that the current bounty policy was reviewed")
	}
	reference := p.PolicyURL
	if p.WrittenAuthorizationReference != "" {
		reference += " | " + p.WrittenAuthorizationReference
	}
	return engagement.Record{
		ID: id, Name: p.Platform + " / " + p.Name, Mode: "bounty", Operator: operator,
		AuthorizationRef: reference, OperatorAttested: true, Scope: p.Scope,
		RateLimitRPS: p.Automation.MaxRequestsRPS, Concurrency: p.Automation.MaxConcurrency,
		AutomationProhibited: !p.Automation.Allowed,
		ExploitAuthorized:    p.HighRisk.Exploitation,
		SocialAuthorized:     p.HighRisk.SocialEngineering,
	}, nil
}
