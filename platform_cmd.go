package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/engagement"
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
		newGuardedStubCommand("recon <target>", "Run authorized asset and service reconnaissance", "nmap", true, false, false),
		newGuardedStubCommand("test <target>", "Run authorized web application testing", "web-test", true, false, false),
		newGuardedStubCommand("exploit <target>", "Run an operator-selected exploit in an authorized engagement", "metasploit", true, true, false),
		newGuardedStubCommand("creds <artifact>", "Audit operator-supplied credential material offline", "hashcat", false, false, true),
		newGuardedStubCommand("wireless <bssid>", "Run an authorized wireless assessment", "aircrack-ng", true, true, false),
		newGuardedStubCommand("se <target>", "Run a sanctioned social-engineering assessment", "set", true, true, false),
		newGuardedStubCommand("ai-redteam <target>", "Evaluate an in-scope LLM application against the shared taxonomy", "ai-redteam", true, false, false),
		newEngagementCmd(),
		newToolsCmd(),
	}
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
	cfg := config.LoadOperational()
	var record *engagement.Record
	if opts.engagementID != "" {
		loaded, err := (engagement.FileStore{Dir: cfg.EngagementDir}).Get(opts.engagementID)
		if err != nil {
			return err
		}
		record = &loaded
	}

	if record != nil {
		recordPolicy := authz.Policy{
			Scope:                 record.Scope,
			AuthorizationAsserted: opts.authorized,
			Engagement:            record.Authorization(),
			KillSwitch:            cfg.KillSwitch,
		}
		if err := recordPolicy.Authorize(cmd.Context(), action); err != nil {
			return fmt.Errorf("engagement authorization refused: %w", err)
		}
		if len(opts.scope) == 0 {
			return nil
		}
	}

	policy := authz.Policy{
		Scope:                 authz.NewScope(opts.scope, opts.denyScope),
		AuthorizationAsserted: opts.authorized,
		KillSwitch:            cfg.KillSwitch,
	}
	if record != nil {
		policy.Engagement = record.Authorization()
	}
	if err := policy.Authorize(cmd.Context(), action); err != nil {
		return fmt.Errorf("authorization refused: %w", err)
	}
	return nil
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
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "tool discovery is scaffolded; full Kali doctor arrives in Phase 3")
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
