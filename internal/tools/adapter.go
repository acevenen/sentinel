// Package tools defines the common contract and normalized result model for
// Sentinel's external security-tool adapters.
package tools

import (
	"context"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
)

// Capability identifies a methodology function an adapter can serve.
type Capability string

// Request is the tool-agnostic input passed to an adapter.
type Request struct {
	Action  authz.Action
	Target  string
	Args    []string
	Secrets []string
	DryRun  bool
	OutDir  string
	Timeout time.Duration
}

// Finding is a normalized security observation shared across all adapters.
type Finding struct {
	ID          string            `json:"id,omitempty"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	CWE         string            `json:"cwe,omitempty"`
	OWASP       string            `json:"owasp,omitempty"`
	Target      string            `json:"target,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Artifact records a file or structured by-product emitted by a tool.
type Artifact struct {
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// Result is the normalized output of any adapter.
type Result struct {
	Tool      string     `json:"tool"`
	Command   []string   `json:"command,omitempty"`
	DryRun    bool       `json:"dry_run"`
	Findings  []Finding  `json:"findings,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	Duration  string     `json:"duration,omitempty"`
}

// AuditEvent is the structured record every active adapter writes.
type AuditEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Operator      string    `json:"operator"`
	EngagementID  string    `json:"engagement_id,omitempty"`
	Target        string    `json:"target"`
	Tool          string    `json:"tool"`
	Arguments     []string  `json:"arguments,omitempty"`
	ScopeDecision string    `json:"scope_decision"`
	Result        string    `json:"result"`
	DryRun        bool      `json:"dry_run"`
}

// Auditor persists active-action audit events. Adapters fail closed when an
// authorized action cannot be audited.
type Auditor interface {
	Record(context.Context, AuditEvent) error
}

// Tool is implemented by every external adapter.
type Tool interface {
	Name() string
	Capabilities() []Capability
	Preflight(context.Context, Request) error
	Run(context.Context, Request) (Result, error)
}
