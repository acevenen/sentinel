package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/hunt"
)

func newHuntImportCmd() *cobra.Command {
	var (
		harPath     string
		identity    string
		programPath string
		outPath     string
		baseURL     string
		name        string
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Build a hunt program manifest from a HAR capture (browser DevTools or Burp)",
		Long: "Import reads a HAR capture — 'Save all as HAR' from browser DevTools' Network tab, or " +
			"Burp Suite's HAR export — and generates a program manifest for `sentinel hunt`. It keeps " +
			"only read-only requests whose path contains an identifier (numeric, UUID, or long hex), " +
			"collapses them into templates (e.g. /orders/1001 and /orders/1002 → /orders/{id}), and " +
			"records the object IDs as owned by --identity.\n\n" +
			"Capture each test account's traffic separately and import both, merging the second into the " +
			"first with --program, so every endpoint has two identities to test across:\n" +
			"  sentinel hunt import --har alice.har --identity alice --out program.yaml\n" +
			"  sentinel hunt import --har bob.har   --identity bob   --program program.yaml --out program.yaml\n\n" +
			"The generated manifest is a starting point: review scope, confirm ownership, and export the " +
			"token env vars before running.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if harPath == "" || identity == "" {
				return fmt.Errorf("--har and --identity are both required")
			}
			harData, err := os.ReadFile(harPath)
			if err != nil {
				return fmt.Errorf("reading HAR: %w", err)
			}

			var base *hunt.Program
			if programPath != "" {
				existing, err := os.ReadFile(programPath)
				if err != nil {
					return fmt.Errorf("reading base program: %w", err)
				}
				p, err := hunt.ParseProgram(existing)
				if err != nil {
					return err
				}
				base = &p
			}

			program, err := hunt.ImportHAR(harData, base, hunt.ImportOptions{
				Identity: identity,
				BaseURL:  baseURL,
				Name:     name,
			})
			if err != nil {
				return err
			}

			out, err := hunt.RenderProgramYAML(program)
			if err != nil {
				return err
			}
			if outPath == "" {
				_, err = os.Stdout.Write(out)
				return err
			}
			if err := os.WriteFile(outPath, out, 0o644); err != nil {
				return fmt.Errorf("writing program file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "sentinel: wrote %d endpoint template(s) for identity %q to %s\n", len(program.Requests), identity, outPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&harPath, "har", "", "path to a HAR capture (required)")
	cmd.Flags().StringVar(&identity, "identity", "", "name of the test account this capture belongs to (required)")
	cmd.Flags().StringVar(&programPath, "program", "", "existing program manifest to merge into (for a second account)")
	cmd.Flags().StringVar(&outPath, "out", "", "write the manifest to this file instead of stdout")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "override the inferred base URL")
	cmd.Flags().StringVar(&name, "name", "", "program name for a fresh manifest")
	return cmd
}
