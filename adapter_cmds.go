package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/engagement"
	"github.com/acevenen/sentinel/internal/tools"
	"github.com/acevenen/sentinel/internal/tools/aircrack"
	"github.com/acevenen/sentinel/internal/tools/hashcat"
	"github.com/acevenen/sentinel/internal/tools/metasploit"
	"github.com/acevenen/sentinel/internal/tools/setoolkit"
	"github.com/acevenen/sentinel/internal/tools/skipfish"
	"github.com/acevenen/sentinel/internal/tools/sqlmap"
	"github.com/acevenen/sentinel/internal/tools/tshark"
)

func runPlatformAdapter(
	cmd *cobra.Command,
	opts activeCommandOptions,
	target string,
	args []string,
	outDir string,
	timeout time.Duration,
	build func(authz.Guardrail, tools.Auditor) tools.Tool,
) error {
	guardrail, err := platformGuardrail(opts)
	if err != nil {
		return err
	}
	cfg := config.LoadOperational()
	adapter := build(guardrail, &engagement.AuditLog{Path: cfg.AuditLog})
	result, err := adapter.Run(cmd.Context(), tools.Request{
		Action: authz.Action{
			Operator: opts.operator, EngagementID: opts.engagementID,
		},
		Target: target, Args: args, DryRun: opts.dryRun, OutDir: outDir, Timeout: timeout,
	})
	if err != nil {
		return err
	}
	return writeJSON(opts.out, result)
}

func newWebTestCmd() *cobra.Command {
	var (
		opts     activeCommandOptions
		toolName string
		toolArgs []string
		outDir   string
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "test <target>",
		Short: "Run guarded web mapping or injection validation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch toolName {
			case "skipfish":
				return runPlatformAdapter(cmd, opts, args[0], toolArgs, outDir, timeout,
					func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
						return skipfish.New(guard, auditor, nil)
					})
			case "sqlmap":
				return runPlatformAdapter(cmd, opts, args[0], toolArgs, outDir, timeout,
					func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
						return sqlmap.New(guard, auditor, nil)
					})
			default:
				return fmt.Errorf("unsupported web test tool %q (want skipfish or sqlmap)", toolName)
			}
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringVar(&toolName, "tool", "skipfish", "guarded adapter: skipfish or sqlmap")
	cmd.Flags().StringSliceVar(&toolArgs, "tool-arg", nil, "operator-selected direct argv (repeatable)")
	cmd.Flags().StringVar(&outDir, "artifact-dir", "", "external tool artifact directory")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Minute, "external tool timeout")
	return cmd
}

func newExploitCmd() *cobra.Command {
	var (
		opts     activeCommandOptions
		resource string
		confirm  bool
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "exploit <target>",
		Short: "Run one operator-selected Metasploit resource under highest guardrails",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				return errors.New("--confirm-intrusive is required for the current exploit action")
			}
			return runPlatformAdapter(cmd, opts, args[0], []string{resource}, "", timeout,
				func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
					return metasploit.New(guard, auditor, nil)
				})
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringVar(&resource, "resource", "", "operator-authored Metasploit resource script (required)")
	cmd.Flags().BoolVar(&confirm, "confirm-intrusive", false, "confirm this specific intrusive action")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Minute, "external tool timeout")
	_ = cmd.MarkFlagRequired("resource")
	return cmd
}

func newCredsCmd() *cobra.Command {
	var (
		opts     activeCommandOptions
		wordlist string
		toolArgs []string
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "creds <hash-artifact>",
		Short: "Audit authorized operator-owned credential material offline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			argv := append([]string{wordlist}, toolArgs...)
			return runPlatformAdapter(cmd, opts, args[0], argv, "", timeout,
				func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
					return hashcat.New(guard, auditor, nil)
				})
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringVar(&wordlist, "wordlist", "", "operator-supplied wordlist (required)")
	cmd.Flags().StringSliceVar(&toolArgs, "tool-arg", nil, "operator-selected direct argv (repeatable)")
	cmd.Flags().DurationVar(&timeout, "timeout", time.Hour, "external tool timeout")
	_ = cmd.MarkFlagRequired("wordlist")
	return cmd
}

func newWirelessCmd() *cobra.Command {
	var (
		opts     activeCommandOptions
		live     bool
		confirm  bool
		toolArgs []string
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "wireless <bssid-or-capture>",
		Short: "Inspect an authorized wireless capture or run confirmed live capture",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			argv := append([]string(nil), toolArgs...)
			if live {
				if !confirm {
					return errors.New("--confirm-intrusive is required for live wireless capture")
				}
				argv = append([]string{"--live"}, argv...)
			}
			return runPlatformAdapter(cmd, opts, args[0], argv, "", timeout,
				func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
					return aircrack.New(guard, auditor, nil)
				})
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().BoolVar(&live, "live", false, "capture from a live authorized BSSID instead of parsing a capture")
	cmd.Flags().BoolVar(&confirm, "confirm-intrusive", false, "confirm this specific intrusive action")
	cmd.Flags().StringSliceVar(&toolArgs, "tool-arg", nil, "operator-selected direct argv (repeatable)")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Minute, "external tool timeout")
	return cmd
}

func newSocialEngineeringCmd() *cobra.Command {
	var (
		opts         activeCommandOptions
		campaignArgs []string
		confirm      bool
		timeout      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "se <target>",
		Short: "Run a written-authorized SET campaign with operator content",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				return errors.New("--confirm-intrusive is required for the current social-engineering action")
			}
			return runPlatformAdapter(cmd, opts, args[0], campaignArgs, "", timeout,
				func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
					return setoolkit.New(guard, auditor, nil)
				})
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().StringSliceVar(&campaignArgs, "campaign-arg", nil, "operator-supplied SET configuration argv (repeatable)")
	cmd.Flags().BoolVar(&confirm, "confirm-intrusive", false, "confirm this specific intrusive action")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Minute, "external tool timeout")
	return cmd
}

func newTrafficCmd() *cobra.Command {
	var (
		opts     activeCommandOptions
		live     bool
		toolArgs []string
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "traffic <pcap-or-interface>",
		Short: "Parse a pcap passively or capture authorized live traffic",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			argv := append([]string(nil), toolArgs...)
			if live {
				argv = append([]string{"--live"}, argv...)
			}
			return runPlatformAdapter(cmd, opts, args[0], argv, "", timeout,
				func(guard authz.Guardrail, auditor tools.Auditor) tools.Tool {
					return tshark.New(guard, auditor, nil)
				})
		},
	}
	addActiveFlags(cmd, &opts)
	cmd.Flags().BoolVar(&live, "live", false, "capture from an interface instead of parsing a pcap")
	cmd.Flags().StringSliceVar(&toolArgs, "tool-arg", nil, "operator-selected direct argv (repeatable)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "external tool timeout")
	return cmd
}
