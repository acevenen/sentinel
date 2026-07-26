package tools

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
)

// CommandBuilder converts a validated request into direct argv.
type CommandBuilder func(Request) (Command, error)

// OutputParser normalizes a completed external process.
type OutputParser func(Execution, Request) ([]Finding, []Artifact, error)

// RequestPredicate classifies a request without trusting caller-supplied
// Action booleans.
type RequestPredicate func(Request) bool

// CommandAdapterConfig defines one external adapter's invariant policy.
type CommandAdapterConfig struct {
	Name                string
	Binary              string
	InstallHint         string
	Capabilities        []Capability
	Active              RequestPredicate
	Intrusive           RequestPredicate
	RequiresAttestation RequestPredicate
	RequiresKali        RequestPredicate
	Validate            func(Request) error
	Build               CommandBuilder
	Parse               OutputParser
	Preflight           func(Request) error
}

// CommandAdapter provides the shared guarded adapter lifecycle.
type CommandAdapter struct {
	config    CommandAdapterConfig
	guard     authz.Guardrail
	auditor   Auditor
	executor  Executor
	lookPath  func(string) (string, error)
	runtimeOK func() error
}

// CommandAdapterOption customizes preflight for tests and non-standard paths.
type CommandAdapterOption func(*CommandAdapter)

// WithAdapterLookPath replaces executable discovery.
func WithAdapterLookPath(lookPath func(string) (string, error)) CommandAdapterOption {
	return func(adapter *CommandAdapter) { adapter.lookPath = lookPath }
}

// WithAdapterRuntimeCheck replaces Kali runtime detection.
func WithAdapterRuntimeCheck(check func() error) CommandAdapterOption {
	return func(adapter *CommandAdapter) { adapter.runtimeOK = check }
}

// WithAdapterPreflightCheck replaces the tool-specific privilege/input check.
// It is intended for deterministic unit tests.
func WithAdapterPreflightCheck(check func(Request) error) CommandAdapterOption {
	return func(adapter *CommandAdapter) { adapter.config.Preflight = check }
}

// NewCommandAdapter constructs a reusable guarded adapter.
func NewCommandAdapter(
	config CommandAdapterConfig,
	guard authz.Guardrail,
	auditor Auditor,
	executor Executor,
	options ...CommandAdapterOption,
) *CommandAdapter {
	if executor == nil {
		executor = OSExecutor{}
	}
	adapter := &CommandAdapter{
		config:    config,
		guard:     guard,
		auditor:   auditor,
		executor:  executor,
		lookPath:  exec.LookPath,
		runtimeOK: RequireKaliForActive,
	}
	for _, option := range options {
		option(adapter)
	}
	return adapter
}

// Name implements Tool.
func (a *CommandAdapter) Name() string { return a.config.Name }

// Binary implements DescribedTool.
func (a *CommandAdapter) Binary() string { return a.config.Binary }

// InstallHint implements DescribedTool.
func (a *CommandAdapter) InstallHint() string { return a.config.InstallHint }

// Capabilities implements Tool.
func (a *CommandAdapter) Capabilities() []Capability {
	return append([]Capability(nil), a.config.Capabilities...)
}

// Preflight validates authorization, runtime, binary, and tool-specific policy.
func (a *CommandAdapter) Preflight(ctx context.Context, request Request) error {
	action, mustAudit, err := a.validateAndAuthorize(ctx, request)
	if err != nil {
		return err
	}
	_ = action
	if mustAudit && a.auditor == nil {
		return fmt.Errorf("%s auditor is required", a.Name())
	}
	command, err := a.config.Build(request)
	if err != nil {
		return err
	}
	return a.preflightRuntime(request, command)
}

// Run executes the standard authorize -> argv -> preflight -> audit -> execute
// -> parse lifecycle. Dry-run stops after audited exact argv construction.
func (a *CommandAdapter) Run(ctx context.Context, request Request) (Result, error) {
	action, mustAudit, authErr := a.validateAndAuthorize(ctx, request)
	if authErr != nil {
		auditErr := a.audit(ctx, request, action, "refused", authErr.Error(), nil, false)
		if auditErr != nil && mustAudit {
			return Result{}, errors.Join(authErr, fmt.Errorf("auditing refusal: %w", auditErr))
		}
		return Result{}, authErr
	}
	command, err := a.config.Build(request)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Tool:    a.Name(),
		Command: append([]string{command.Path}, command.Args...),
		DryRun:  request.DryRun,
	}
	if request.DryRun {
		if err := a.audit(ctx, request, action, "allowed", "dry-run", result.Command, mustAudit); err != nil {
			return Result{}, fmt.Errorf("auditing %s dry-run: %w", a.Name(), err)
		}
		return result, nil
	}
	if err := a.preflightRuntime(request, command); err != nil {
		_ = a.audit(ctx, request, action, "allowed", "preflight failed: "+err.Error(), result.Command, mustAudit)
		return Result{}, err
	}
	if err := a.audit(ctx, request, action, "allowed", "execution started", result.Command, mustAudit); err != nil {
		return Result{}, fmt.Errorf("auditing %s start: %w", a.Name(), err)
	}

	start := time.Now()
	execution, err := a.executor.Execute(ctx, command)
	result.StartedAt = start.UTC()
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	if err != nil {
		_ = a.audit(ctx, request, action, "allowed", "execution failed: "+err.Error(), result.Command, mustAudit)
		return result, err
	}
	if execution.Truncated {
		err := fmt.Errorf("%s output exceeded the configured output cap", a.Name())
		_ = a.audit(ctx, request, action, "allowed", err.Error(), result.Command, mustAudit)
		return result, err
	}
	if a.config.Parse != nil {
		findings, artifacts, err := a.config.Parse(execution, request)
		if err != nil {
			_ = a.audit(ctx, request, action, "allowed", "parse failed: "+err.Error(), result.Command, mustAudit)
			return result, err
		}
		result.Findings = findings
		result.Artifacts = artifacts
	}
	if err := a.audit(ctx, request, action, "allowed",
		fmt.Sprintf("completed with %d findings and %d artifacts", len(result.Findings), len(result.Artifacts)),
		result.Command, mustAudit); err != nil {
		return Result{}, fmt.Errorf("auditing %s completion: %w", a.Name(), err)
	}
	return result, nil
}

func (a *CommandAdapter) validateAndAuthorize(ctx context.Context, request Request) (authz.Action, bool, error) {
	if strings.TrimSpace(request.Target) == "" {
		return authz.Action{}, false, fmt.Errorf("%s target is required", a.Name())
	}
	if a.config.Build == nil {
		return authz.Action{}, false, fmt.Errorf("%s command builder is required", a.Name())
	}
	if a.config.Validate != nil {
		if err := a.config.Validate(request); err != nil {
			return authz.Action{}, false, err
		}
	}
	if a.guard == nil {
		return authz.Action{}, false, fmt.Errorf("%s guardrail is required", a.Name())
	}
	action := request.Action
	action.Tool = a.Name()
	action.Target = request.Target
	action.Arguments = append([]string(nil), request.Args...)
	action.Active = predicate(a.config.Active, request)
	action.Intrusive = predicate(a.config.Intrusive, request)
	action.RequiresAttestation = predicate(a.config.RequiresAttestation, request)
	mustAudit := action.Active || action.Intrusive || action.RequiresAttestation
	if mustAudit && a.auditor == nil {
		return action, mustAudit, fmt.Errorf("%s auditor is required", a.Name())
	}
	if err := a.guard.Authorize(ctx, action); err != nil {
		return action, mustAudit, fmt.Errorf("%s authorization refused: %w", a.Name(), err)
	}
	return action, mustAudit, nil
}

func (a *CommandAdapter) preflightRuntime(request Request, command Command) error {
	if predicate(a.config.RequiresKali, request) {
		if err := a.runtimeOK(); err != nil {
			return err
		}
	}
	if _, err := a.lookPath(command.Path); err != nil {
		return fmt.Errorf("%s binary %q is unavailable; %s: %w", a.Name(), command.Path, a.InstallHint(), err)
	}
	if a.config.Preflight != nil {
		return a.config.Preflight(request)
	}
	return nil
}

func (a *CommandAdapter) audit(
	ctx context.Context,
	request Request,
	action authz.Action,
	decision string,
	result string,
	command []string,
	required bool,
) error {
	if a.auditor == nil {
		if required {
			return fmt.Errorf("%s auditor is required", a.Name())
		}
		return nil
	}
	if len(command) == 0 {
		command = append([]string{a.config.Binary}, request.Args...)
		command = append(command, request.Target)
	}
	return a.auditor.Record(ctx, AuditEvent{
		Timestamp:     time.Now().UTC(),
		Operator:      action.Operator,
		EngagementID:  action.EngagementID,
		Target:        action.Target,
		Tool:          a.Name(),
		Arguments:     RedactArgs(command[1:], request.Secrets),
		ScopeDecision: decision,
		Result:        result,
		DryRun:        request.DryRun,
	})
}

func predicate(check RequestPredicate, request Request) bool {
	return check != nil && check(request)
}

var _ Tool = (*CommandAdapter)(nil)
var _ DescribedTool = (*CommandAdapter)(nil)
