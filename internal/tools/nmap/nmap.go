// Package nmap implements Sentinel's guarded nmap adapter for host, port, and
// service discovery using nmap's machine-readable XML output.
package nmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

const defaultBinary = "nmap"

// ErrPrivilegeRequired means the selected scan needs root or CAP_NET_RAW.
var ErrPrivilegeRequired = errors.New("nmap SYN scan requires root or CAP_NET_RAW; Sentinel never escalates automatically")

// Adapter wraps nmap behind the shared guardrail and executor.
type Adapter struct {
	guard      authz.Guardrail
	auditor    tools.Auditor
	executor   tools.Executor
	binary     string
	lookPath   func(string) (string, error)
	hasRawCaps func() bool
	runtimeOK  func() error
}

// Option customizes adapter discovery for testing or non-standard installs.
type Option func(*Adapter)

// WithBinary selects a non-default nmap executable.
func WithBinary(binary string) Option {
	return func(adapter *Adapter) { adapter.binary = binary }
}

// WithLookPath replaces binary discovery.
func WithLookPath(lookPath func(string) (string, error)) Option {
	return func(adapter *Adapter) { adapter.lookPath = lookPath }
}

// WithRawCapabilityCheck replaces the privilege check.
func WithRawCapabilityCheck(check func() bool) Option {
	return func(adapter *Adapter) { adapter.hasRawCaps = check }
}

// WithRuntimeCheck replaces Kali environment detection.
func WithRuntimeCheck(check func() error) Option {
	return func(adapter *Adapter) { adapter.runtimeOK = check }
}

// New constructs an nmap adapter. Guardrail and auditor are mandatory for Run.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...Option) *Adapter {
	if executor == nil {
		executor = tools.OSExecutor{}
	}
	adapter := &Adapter{
		guard:      guard,
		auditor:    auditor,
		executor:   executor,
		binary:     defaultBinary,
		lookPath:   exec.LookPath,
		hasRawCaps: hasRawSocketCapability,
		runtimeOK:  tools.RequireKaliForActive,
	}
	for _, option := range options {
		option(adapter)
	}
	return adapter
}

// Name implements tools.Tool.
func (a *Adapter) Name() string { return "nmap" }

// Binary implements tools.DescribedTool.
func (a *Adapter) Binary() string { return a.binary }

// InstallHint implements tools.DescribedTool.
func (a *Adapter) InstallHint() string {
	return "run `make dev`; nmap is installed in Sentinel's Kali Dev Container"
}

// Capabilities implements tools.Tool.
func (a *Adapter) Capabilities() []tools.Capability {
	return []tools.Capability{
		"recon.host-discovery",
		"recon.port-scan",
		"recon.service-version",
	}
}

// Preflight verifies input, authorization, binary availability, and privilege.
func (a *Adapter) Preflight(ctx context.Context, request tools.Request) error {
	if _, err := a.validateAndAuthorize(ctx, request); err != nil {
		return err
	}
	return a.preflightRuntime(request)
}

// Run authorizes before building or executing argv. Dry-run returns the exact
// command without requiring nmap to be installed.
func (a *Adapter) Run(ctx context.Context, request tools.Request) (tools.Result, error) {
	action, authErr := a.validateAndAuthorize(ctx, request)
	if authErr != nil {
		_ = a.audit(ctx, request, action, "refused", authErr.Error())
		return tools.Result{}, authErr
	}

	command := a.buildCommand(request)
	result := tools.Result{
		Tool:    a.Name(),
		Command: append([]string{command.Path}, command.Args...),
		DryRun:  request.DryRun,
	}
	if request.DryRun {
		if err := a.audit(ctx, request, action, "allowed", "dry-run"); err != nil {
			return tools.Result{}, fmt.Errorf("auditing nmap dry-run: %w", err)
		}
		return result, nil
	}
	if err := a.preflightRuntime(request); err != nil {
		_ = a.audit(ctx, request, action, "allowed", "preflight failed: "+err.Error())
		return tools.Result{}, err
	}
	if err := a.audit(ctx, request, action, "allowed", "execution started"); err != nil {
		return tools.Result{}, fmt.Errorf("auditing nmap start: %w", err)
	}

	start := time.Now()
	execution, err := a.executor.Execute(ctx, command)
	result.StartedAt = start.UTC()
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	if err != nil {
		_ = a.audit(ctx, request, action, "allowed", "execution failed: "+err.Error())
		return result, err
	}
	if execution.Truncated {
		err := errors.New("nmap output exceeded the configured output cap")
		_ = a.audit(ctx, request, action, "allowed", err.Error())
		return result, err
	}
	findings, err := ParseXML(execution.Stdout)
	if err != nil {
		_ = a.audit(ctx, request, action, "allowed", "parse failed: "+err.Error())
		return result, err
	}
	result.Findings = findings
	if err := a.audit(ctx, request, action, "allowed", fmt.Sprintf("completed with %d findings", len(findings))); err != nil {
		return tools.Result{}, fmt.Errorf("auditing nmap completion: %w", err)
	}
	return result, nil
}

func (a *Adapter) validateAndAuthorize(ctx context.Context, request tools.Request) (authz.Action, error) {
	if strings.TrimSpace(request.Target) == "" {
		return authz.Action{}, errors.New("nmap target is required")
	}
	if a.guard == nil {
		return authz.Action{}, errors.New("nmap guardrail is required")
	}
	if a.auditor == nil {
		return authz.Action{}, errors.New("nmap auditor is required")
	}
	action := request.Action
	action.Tool = a.Name()
	action.Target = request.Target
	action.Arguments = append([]string(nil), request.Args...)
	action.Active = true
	if err := a.guard.Authorize(ctx, action); err != nil {
		return action, fmt.Errorf("nmap authorization refused: %w", err)
	}
	return action, nil
}

func (a *Adapter) preflightRuntime(request tools.Request) error {
	if err := a.runtimeOK(); err != nil {
		return err
	}
	if _, err := a.lookPath(a.binary); err != nil {
		return fmt.Errorf("nmap binary %q is unavailable; %s: %w", a.binary, a.InstallHint(), err)
	}
	if requestsSYNScan(request.Args) && !a.hasRawCaps() {
		return ErrPrivilegeRequired
	}
	return nil
}

func (a *Adapter) buildCommand(request tools.Request) tools.Command {
	args := make([]string, 0, len(request.Args)+3)
	args = append(args, "-oX", "-")
	args = append(args, request.Args...)
	args = append(args, request.Target)
	return tools.Command{
		Path:        a.binary,
		Args:        args,
		Timeout:     request.Timeout,
		OutputLimit: 16 << 20,
	}
}

func (a *Adapter) audit(ctx context.Context, request tools.Request, action authz.Action, decision, result string) error {
	if a.auditor == nil {
		return errors.New("nmap auditor is required")
	}
	args := append([]string{"-oX", "-"}, request.Args...)
	args = append(args, request.Target)
	return a.auditor.Record(ctx, tools.AuditEvent{
		Timestamp:     time.Now().UTC(),
		Operator:      action.Operator,
		EngagementID:  action.EngagementID,
		Target:        action.Target,
		Tool:          a.Name(),
		Arguments:     tools.RedactArgs(args, request.Secrets),
		ScopeDecision: decision,
		Result:        result,
		DryRun:        request.DryRun,
	})
}

func requestsSYNScan(args []string) bool {
	for _, arg := range args {
		if arg == "-sS" || strings.Contains(arg, "sS") && strings.HasPrefix(arg, "-") {
			return true
		}
	}
	return false
}

func hasRawSocketCapability() bool {
	if os.Geteuid() == 0 {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		const capNetRaw = uint64(1 << 13)
		return value&capNetRaw != 0
	}
	return false
}

var _ tools.Tool = (*Adapter)(nil)
var _ tools.DescribedTool = (*Adapter)(nil)
