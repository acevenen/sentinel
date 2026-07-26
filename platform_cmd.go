package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/engagement"
	"github.com/acevenen/sentinel/internal/methodology"
	"github.com/acevenen/sentinel/internal/orchestrator"
	"github.com/acevenen/sentinel/internal/redteam"
	"github.com/acevenen/sentinel/internal/tools"
	"github.com/acevenen/sentinel/internal/tools/nmap"
)

type activeCommandOptions struct {
	scope        []string
	denyScope    []string
	engagementID string
	dryRun       bool
	out          string
	authorized   bool
	operator     string
}

func newPlatformCommands() []*cobra.Command {
	return []*cobra.Command{
		newReconCmd(),
		newGuardedStubCommand("test <target>", "Run authorized web application testing", "web-test", true, false, false),
		newGuardedStubCommand("exploit <target>", "Run an operator-selected exploit in an authorized engagement", "metasploit", true, true, false),
		newGuardedStubCommand("creds <artifact>", "Audit operator-supplied credential material offline", "hashcat", false, false, true),
		newGuardedStubCommand("wireless <bssid>", "Run an authorized wireless assessment", "aircrack-ng", true, true, false),
		newGuardedStubCommand("se <target>", "Run a sanctioned social-engineering assessment", "set", true, true, false),
		newAIRedTeamCmd(),
		newOrchestrateCmd(),
		newEngagementCmd(),
		newToolsCmd(),
	}
}

func newOrchestrateCmd() *cobra.Command {
	var (
		opts             activeCommandOptions
		contentPaths     []string
		plannerMode      string
		model            string
		confirmIntrusive bool
	)
	cmd := &cobra.Command{
		Use:   "orchestrate <target>",
		Short: "Produce a guarded, human-reviewed methodology plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.engagementID == "" {
				return errors.New("--engagement is required for resumable orchestration")
			}
			cfg := config.LoadOperational()
			state, err := (methodology.FileStateStore{Dir: cfg.StateDir}).Load(opts.engagementID)
			if errors.Is(err, os.ErrNotExist) {
				state = methodology.RunState{EngagementID: opts.engagementID}
			} else if err != nil {
				return err
			}
			observations := make([]orchestrator.Observation, 0, len(contentPaths))
			for _, path := range contentPaths {
				content, err := readPlanningContent(path)
				if err != nil {
					return err
				}
				observations = append(observations, orchestrator.Observation{Source: "tool", Content: content})
			}
			var planner orchestrator.Planner
			switch plannerMode {
			case "methodology":
				planner = orchestrator.MethodologyPlanner{}
			case "claude":
				apiKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
				if apiKey == "" {
					return errors.New("ANTHROPIC_API_KEY is required for --planner claude")
				}
				planner = orchestrator.ClaudePlanner{Client: analyzer.NewClient(apiKey, model)}
			case "auto":
				if apiKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); apiKey != "" {
					planner = orchestrator.ClaudePlanner{Client: analyzer.NewClient(apiKey, model)}
				} else {
					planner = orchestrator.MethodologyPlanner{}
				}
			default:
				return fmt.Errorf("unsupported planner %q (want auto, claude, or methodology)", plannerMode)
			}
			guardrail, err := platformGuardrail(opts)
			if err != nil {
				return err
			}
			engine := orchestrator.Engine{
				Planner: planner,
				Guard:   guardrail,
				Auditor: &engagement.AuditLog{Path: cfg.AuditLog},
			}
			report, runErr := engine.Run(cmd.Context(), orchestrator.PlanningInput{
				EngagementID: opts.engagementID, Operator: opts.operator,
				Target: args[0], State: state, Observations: observations,
			}, orchestrator.RunOptions{
				ConfirmIntrusive: confirmIntrusive,
				DryRun:           opts.dryRun,
			})
			if err := writeJSON(opts.out, report); err != nil {
				return err
			}
			return runErr
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringSliceVar(&contentPaths, "content", nil, "captured target-content file to inspect before planning (repeatable)")
	cmd.Flags().StringVar(&plannerMode, "planner", "auto", "planner: auto, claude, or methodology")
	cmd.Flags().StringVar(&model, "model", config.DefaultModel, "Anthropic model for Claude planning")
	cmd.Flags().BoolVar(&confirmIntrusive, "confirm-intrusive", false, "explicitly confirm the current intrusive proposal")
	return cmd
}

func readPlanningContent(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening planning content: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil {
		return "", fmt.Errorf("reading planning content: %w", err)
	}
	if len(data) > 2<<20 {
		return "", errors.New("planning content exceeds 2 MiB")
	}
	return string(data), nil
}

func newAIRedTeamCmd() *cobra.Command {
	var (
		opts          activeCommandOptions
		suitePath     string
		taxonomyPath  string
		targetMode    string
		approveProbes bool
		timeout       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "ai-redteam <target>",
		Short: "Run an approved taxonomy-structured suite against an in-scope LLM app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			suite, err := redteam.LoadSuiteFile(suitePath)
			if err != nil {
				return err
			}
			taxonomy, err := redteam.Core()
			if err != nil {
				return err
			}
			if taxonomyPath != "" {
				data, readErr := os.ReadFile(taxonomyPath)
				if readErr != nil {
					return readErr
				}
				taxonomy, err = redteam.Load(data)
				if err != nil {
					return err
				}
			}
			guardrail, err := platformGuardrail(opts)
			if err != nil {
				return err
			}
			cfg := config.LoadOperational()
			runner := redteam.Runner{
				Guard:    guardrail,
				Auditor:  &engagement.AuditLog{Path: cfg.AuditLog},
				Client:   &http.Client{Timeout: timeout},
				Taxonomy: taxonomy,
			}
			result, err := runner.Run(cmd.Context(), suite, redteam.RunOptions{
				Target: args[0], EngagementID: opts.engagementID, Operator: opts.operator,
				Mode: redteam.TargetMode(targetMode), Approved: approveProbes, DryRun: opts.dryRun,
			})
			if err != nil {
				return err
			}
			return writeJSON(opts.out, result)
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringVar(&suitePath, "suite", "", "operator-reviewed probe suite JSON (required)")
	cmd.Flags().StringVar(&taxonomyPath, "taxonomy", "", "optional official Arcanum taxonomy JSON")
	cmd.Flags().StringVar(&targetMode, "target-mode", string(redteam.TargetBlackBox), "target access: black-box or local")
	cmd.Flags().BoolVar(&approveProbes, "approve-probes", false, "confirm the operator reviewed and approved every suite probe")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "per-request HTTP timeout")
	_ = cmd.MarkFlagRequired("suite")
	return cmd
}

func newReconCmd() *cobra.Command {
	var (
		opts     activeCommandOptions
		nmapArgs []string
	)
	cmd := &cobra.Command{
		Use:   "recon <target>",
		Short: "Run authorized asset and service reconnaissance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			guardrail, err := platformGuardrail(opts)
			if err != nil {
				return err
			}
			cfg := config.LoadOperational()
			auditor := &engagement.AuditLog{Path: cfg.AuditLog}
			adapter := nmap.New(guardrail, auditor, nil)
			result, err := adapter.Run(cmd.Context(), tools.Request{
				Action: authz.Action{
					Operator:     opts.operator,
					EngagementID: opts.engagementID,
				},
				Target: args[0],
				Args:   nmapArgs,
				DryRun: opts.dryRun,
			})
			if err != nil {
				return err
			}

			report := struct {
				Stage        methodology.Stage     `json:"stage"`
				ToolResult   tools.Result          `json:"tool_result"`
				Methodology  *methodology.RunState `json:"methodology_state,omitempty"`
				ProposedNext []methodology.Stage   `json:"proposed_next"`
			}{
				Stage:        methodology.StageRecon,
				ToolResult:   result,
				ProposedNext: []methodology.Stage{methodology.StageApplicationMapping},
			}
			if !opts.dryRun && opts.engagementID != "" {
				store := methodology.FileStateStore{Dir: cfg.StateDir}
				state, loadErr := store.Load(opts.engagementID)
				if errors.Is(loadErr, os.ErrNotExist) {
					state = methodology.RunState{EngagementID: opts.engagementID}
				} else if loadErr != nil {
					return loadErr
				}
				workflow := methodology.Workflow{Runner: methodology.StageRunnerFunc(
					func(context.Context, methodology.Stage, methodology.RunState) ([]tools.Finding, error) {
						return result.Findings, nil
					},
				)}
				state, err = workflow.RunStage(cmd.Context(), state, methodology.StageRecon)
				if err != nil {
					return err
				}
				if err := store.Save(state); err != nil {
					return err
				}
				report.Methodology = &state
				report.ProposedNext = state.ProposedNext
			}
			return writeJSON(opts.out, report)
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringSliceVar(&nmapArgs, "nmap-arg", nil, "operator-selected nmap argv (repeatable; no shell interpolation)")
	return cmd
}

func newGuardedStubCommand(use, short, tool string, active, intrusive, attestation bool) *cobra.Command {
	var opts activeCommandOptions
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := authz.Action{
				Operator:            opts.operator,
				EngagementID:        opts.engagementID,
				Target:              args[0],
				Tool:                tool,
				Active:              active,
				Intrusive:           intrusive,
				RequiresAttestation: attestation,
			}
			if err := authorizePlatformAction(cmd, opts, action); err != nil {
				return err
			}
			if active && !opts.dryRun {
				if err := tools.RequireKaliForActive(); err != nil {
					return err
				}
			}

			plan := struct {
				Phase   int          `json:"phase"`
				DryRun  bool         `json:"dry_run"`
				Action  authz.Action `json:"action"`
				Status  string       `json:"status"`
				Warning string       `json:"warning"`
			}{
				Phase:   1,
				DryRun:  opts.dryRun,
				Action:  action,
				Status:  "authorized; adapter scaffold only",
				Warning: "no external command is enabled in Phase 1",
			}
			if opts.dryRun {
				return writeJSON(opts.out, plan)
			}
			return fmt.Errorf("%s adapter is scaffolded but intentionally disabled until its guarded implementation phase; use --dry-run to inspect the authorized plan", tool)
		},
	}
	addActiveFlags(cmd, &opts)
	return cmd
}

func addActiveFlags(cmd *cobra.Command, opts *activeCommandOptions) {
	cmd.Flags().StringSliceVar(&opts.scope, "scope", nil, "explicit allow-list (domain, IP, CIDR, URL, BSSID, or engagement ID)")
	cmd.Flags().StringSliceVar(&opts.denyScope, "deny-scope", nil, "explicit deny-list; always overrides the allow-list")
	cmd.Flags().StringVar(&opts.engagementID, "engagement", "", "engagement record identifier")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "authorize and print the exact plan without executing it")
	cmd.Flags().StringVar(&opts.out, "out", "", "write structured output to a file instead of stdout")
	cmd.Flags().BoolVar(&opts.authorized, "authorized", false, "assert that the operator is authorized for this active action")
	cmd.Flags().StringVar(&opts.operator, "operator", defaultOperator(), "operator identity recorded in authorization and audit events")
}

func authorizePlatformAction(cmd *cobra.Command, opts activeCommandOptions, action authz.Action) error {
	guardrail, err := platformGuardrail(opts)
	if err != nil {
		return err
	}
	if err := guardrail.Authorize(cmd.Context(), action); err != nil {
		return fmt.Errorf("authorization refused: %w", err)
	}
	return nil
}

func platformGuardrail(opts activeCommandOptions) (authz.Guardrail, error) {
	cfg := config.LoadOperational()
	var record *engagement.Record
	if opts.engagementID != "" {
		loaded, err := (engagement.FileStore{Dir: cfg.EngagementDir}).Get(opts.engagementID)
		if err != nil {
			return nil, err
		}
		record = &loaded
	}

	var guardrails authz.Chain
	if record != nil {
		recordScope := record.Scope
		recordScope.Deny = append(recordScope.Deny, opts.denyScope...)
		recordPolicy := authz.Policy{
			Scope:                 recordScope,
			AuthorizationAsserted: opts.authorized,
			Engagement:            record.Authorization(),
			KillSwitch:            cfg.KillSwitch,
		}
		guardrails = append(guardrails, recordPolicy)
	}

	if record == nil || len(opts.scope) > 0 {
		policy := authz.Policy{
			Scope:                 authz.NewScope(opts.scope, opts.denyScope),
			AuthorizationAsserted: opts.authorized,
			KillSwitch:            cfg.KillSwitch,
		}
		if record != nil {
			policy.Engagement = record.Authorization()
		}
		guardrails = append(guardrails, policy)
	}
	if len(guardrails) == 1 {
		return guardrails[0], nil
	}
	return guardrails, nil
}

func newEngagementCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "engagement",
		Short: "Create, list, and scope authorization records",
		Args:  cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&out, "out", "", "write structured output to a file instead of stdout")
	cmd.AddCommand(newEngagementCreateCmd(&out), newEngagementListCmd(&out), newEngagementScopeCmd(&out))
	return cmd
}

func newEngagementCreateCmd(out *string) *cobra.Command {
	var (
		id               string
		name             string
		operator         string
		authorizationRef string
		attest           bool
		allow            []string
		deny             []string
		rate             float64
		concurrency      int
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an engagement record",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if id == "" || name == "" {
				return errors.New("--id and --name are required")
			}
			record := engagement.Record{
				ID:               id,
				Name:             name,
				Operator:         operator,
				AuthorizationRef: authorizationRef,
				OperatorAttested: attest,
				Scope:            authz.NewScope(allow, deny),
				RateLimitRPS:     rate,
				Concurrency:      concurrency,
				CreatedAt:        time.Now().UTC(),
			}
			store := engagement.FileStore{Dir: config.LoadOperational().EngagementDir}
			if err := store.Save(record); err != nil {
				return err
			}
			saved, err := store.Get(id)
			if err != nil {
				return err
			}
			return writeJSON(*out, saved)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "portable engagement identifier (required)")
	cmd.Flags().StringVar(&name, "name", "", "human-readable engagement name (required)")
	cmd.Flags().StringVar(&operator, "operator", defaultOperator(), "accountable operator identity")
	cmd.Flags().StringVar(&authorizationRef, "authorization-ref", "", "signed rules-of-engagement or authorization reference")
	cmd.Flags().BoolVar(&attest, "attest", false, "attest that the operator has verified the authorization reference")
	cmd.Flags().StringSliceVar(&allow, "scope", nil, "initial allow-list")
	cmd.Flags().StringSliceVar(&deny, "deny-scope", nil, "initial deny-list")
	cmd.Flags().Float64Var(&rate, "rate-limit", 0, "maximum active requests per second")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "maximum concurrent active actions")
	return cmd
}

func newEngagementListCmd(out *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List local engagement records",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			records, err := (engagement.FileStore{Dir: config.LoadOperational().EngagementDir}).List()
			if err != nil {
				return err
			}
			return writeJSON(*out, records)
		},
	}
}

func newEngagementScopeCmd(out *string) *cobra.Command {
	var (
		id    string
		allow []string
		deny  []string
	)
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Replace an engagement's explicit allow and deny lists",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if id == "" {
				return errors.New("--engagement is required")
			}
			store := engagement.FileStore{Dir: config.LoadOperational().EngagementDir}
			record, err := store.Get(id)
			if err != nil {
				return err
			}
			record.Scope = authz.NewScope(allow, deny)
			if err := store.Save(record); err != nil {
				return err
			}
			updated, err := store.Get(id)
			if err != nil {
				return err
			}
			return writeJSON(*out, updated)
		},
	}
	cmd.Flags().StringVar(&id, "engagement", "", "engagement record identifier (required)")
	cmd.Flags().StringSliceVar(&allow, "scope", nil, "replacement allow-list")
	cmd.Flags().StringSliceVar(&deny, "deny-scope", nil, "replacement deny-list")
	return cmd
}

func newToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Inspect Sentinel's external toolchain",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Report adapter and Kali runtime readiness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status := tools.DetectRuntime()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Kali runtime: %v  container: %v  platform: %s/%s\n",
				status.Kali, status.InContainer, status.GOOS, status.GOARCH)
			for _, item := range status.Tools {
				state := "MISSING"
				detail := item.InstallHint
				if item.Available {
					state = "READY"
					detail = item.Path
				}
				fmt.Fprintf(out, "  %-8s %-20s %s\n", state, item.Name, detail)
			}
			if status.Ready {
				_, err := fmt.Fprintln(out, "Toolchain ready.")
				return err
			}
			_, err := fmt.Fprintln(out, status.Instruction)
			return err
		},
	})
	return cmd
}

func writeJSON(out string, value any) error {
	return writeReport(out, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	})
}

func defaultOperator() string {
	for _, key := range []string{"SENTINEL_OPERATOR", "USER", "USERNAME"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return "unknown"
}
