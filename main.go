// Command sentinel is a defensive AI-powered code review agent. It scans a
// codebase for security vulnerabilities using the Anthropic API and reports
// findings with severity levels.
//
// Exit codes: 0 = clean, 1 = findings at/above the severity threshold,
// 2 = tool error — so it can gate CI pipelines.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/report"
	"github.com/acevenen/sentinel/internal/scanner"
)

// version is stamped by the release workflow via -ldflags. For go-install
// builds it falls back to the module version from the build info.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

// errFindings signals exit code 1: the scan worked but found issues.
var errFindings = errors.New("findings at or above severity threshold")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd()
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
	case errors.Is(err, errFindings):
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sentinel",
		Short:         "AI-powered defensive security code review",
		Long:          "Sentinel scans a codebase for security vulnerabilities and code quality issues using the Anthropic API.",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newScanCmd(), newGuardCmd(), newEvaluateCmd(), newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the sentinel version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "sentinel %s\n", version)
		},
	}
}

func newScanCmd() *cobra.Command {
	var (
		format      string
		severity    string
		out         string
		include     []string
		exclude     []string
		concurrency int
		model       string
	)

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a directory for security issues",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			info, err := os.Stat(target)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", target)
			}

			cfg, err := config.Load(target)
			if err != nil {
				return err
			}

			// Flags win over env and file config, but only when set.
			flags := cmd.Flags()
			if flags.Changed("format") {
				cfg.Format = format
			}
			if flags.Changed("severity") {
				cfg.Severity = severity
			}
			if flags.Changed("out") {
				cfg.Out = out
			}
			if flags.Changed("include") {
				cfg.Include = include
			}
			if flags.Changed("exclude") {
				cfg.Exclude = exclude
			}
			if flags.Changed("concurrency") {
				cfg.Concurrency = concurrency
			}
			if flags.Changed("model") {
				cfg.Model = model
			}

			if err := cfg.Validate(); err != nil {
				return err
			}
			if cfg.APIKey == "" {
				return errors.New("ANTHROPIC_API_KEY is not set; export it before scanning (the key is never stored)")
			}

			return runScan(cmd.Context(), target, cfg)
		},
	}

	cmd.Flags().StringVar(&format, "format", report.FormatTerminal, fmt.Sprintf("output format: %v", report.Formats))
	cmd.Flags().StringVar(&severity, "severity", string(analyzer.SeverityLow), "minimum severity to report: low|medium|high|critical")
	cmd.Flags().StringVar(&out, "out", "", "write the report to a file instead of stdout")
	cmd.Flags().StringSliceVar(&include, "include", nil, "only scan files matching these globs (e.g. '**/*.go')")
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "skip files matching these globs")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "number of concurrent analysis requests")
	cmd.Flags().StringVar(&model, "model", config.DefaultModel, "Anthropic model to use")
	return cmd
}

func runScan(ctx context.Context, target string, cfg config.Config) error {
	start := time.Now()

	result, err := scanner.Scan(scanner.Options{
		Root:    target,
		Include: cfg.Include,
		Exclude: cfg.Exclude,
	})
	if err != nil {
		return fmt.Errorf("scanning %s: %w", target, err)
	}
	if len(result.Chunks) == 0 {
		fmt.Fprintln(os.Stderr, "sentinel: no source files found to analyze")
		return nil
	}

	fmt.Fprintf(os.Stderr, "sentinel: analyzing %d files (%d chunks) with %s, concurrency %d\n",
		result.Files, len(result.Chunks), cfg.Model, cfg.Concurrency)

	client := analyzer.NewClient(cfg.APIKey, cfg.Model)
	findings, errs := analyzer.New(client, cfg.Concurrency).Run(ctx, result.Chunks,
		func(done, total int) {
			fmt.Fprintf(os.Stderr, "\rsentinel: analyzed %d/%d chunks", done, total)
		})
	fmt.Fprintln(os.Stderr)

	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "sentinel: warning: %v\n", e)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("scan interrupted: %w", ctx.Err())
	}
	if len(errs) > 0 && len(errs) == len(result.Chunks) {
		return errors.New("every analysis request failed; see warnings above")
	}

	filtered := report.FilterBySeverity(findings, cfg.MinSeverity())
	rep := &report.Report{
		Tool:        "sentinel",
		Version:     version,
		Path:        target,
		Model:       cfg.Model,
		Files:       result.Files,
		Chunks:      len(result.Chunks),
		Duration:    time.Since(start),
		GeneratedAt: time.Now().UTC(),
		Findings:    filtered,
	}

	var dest io.Writer = os.Stdout
	var closeReport func() error
	if cfg.Out != "" {
		f, err := os.Create(cfg.Out)
		if err != nil {
			return fmt.Errorf("creating report file: %w", err)
		}
		dest = f
		closeReport = f.Close
		color.NoColor = true // never write ANSI codes into files
	}

	if err := report.Render(dest, cfg.Format, rep); err != nil {
		return err
	}
	if closeReport != nil {
		if err := closeReport(); err != nil {
			return fmt.Errorf("writing report file: %w", err)
		}
	}

	if len(filtered) > 0 {
		return errFindings
	}
	return nil
}
