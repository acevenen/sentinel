package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/hunt"
	"github.com/acevenen/sentinel/internal/report"
)

func newHuntCmd() *cobra.Command {
	var (
		programPath string
		format      string
		outPath     string
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Test an authorized bug-bounty target for IDOR/BOLA (broken object-level authorization)",
		Long: "Hunt reads a program manifest describing an authorized bug-bounty program's scope " +
			"and your own test identities, then runs a read-only differential test: it fetches each " +
			"identity's own objects to establish a baseline, then replays one identity's objects using " +
			"another identity's session. If an attacker identity receives a victim's object, object-level " +
			"authorization is broken.\n\n" +
			"Hunt is scope-first and safe by construction: every request is checked against the declared " +
			"scope before it is sent (out-of-scope hosts are refused), it uses only test accounts you " +
			"control (tokens from the environment, never stored), it is read-only so it never mutates " +
			"target data, and it is rate-limited. Only run it against programs that authorize testing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if programPath == "" {
				return fmt.Errorf("--program is required (path to a program manifest yaml)")
			}
			program, err := hunt.LoadProgram(programPath)
			if err != nil {
				return err
			}

			// Session tokens come from the environment, one per identity, and are
			// never read from the manifest or written anywhere.
			tokens := map[string]string{}
			var missing []string
			for _, id := range program.Identities {
				if tok := os.Getenv(id.TokenEnv); tok != "" {
					tokens[id.Name] = tok
				} else {
					missing = append(missing, fmt.Sprintf("%s (%s)", id.Name, id.TokenEnv))
				}
			}

			engine := hunt.NewEngine(program, hunt.DefaultTransport(), tokens)

			if dryRun {
				report.RenderHuntPlan(os.Stdout, program.Name, engine.Plan())
				return nil
			}

			if len(missing) > 0 {
				return fmt.Errorf("missing session token(s) for: %v — export them before running (or use --dry-run)", missing)
			}

			rep, err := engine.Run(cmd.Context())
			if err != nil {
				return err
			}

			dest := os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("creating report file: %w", err)
				}
				defer func() { _ = f.Close() }()
				dest = f
				color.NoColor = true
			}
			if err := report.RenderHunt(dest, format, rep); err != nil {
				return err
			}

			if len(rep.Findings) > 0 {
				return errFindings
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&programPath, "program", "", "path to the program manifest yaml (required)")
	cmd.Flags().StringVar(&format, "format", report.HuntFormatTerminal, "output format: terminal, json, or markdown (HackerOne-ready)")
	cmd.Flags().StringVar(&outPath, "out", "", "write the report to a file instead of stdout")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the planned requests and scope decisions without sending anything")
	return cmd
}
