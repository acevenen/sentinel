package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/confidence"
	"github.com/acevenen/sentinel/reverso/internal/report"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate evidence-backed reports",
	}
	cmd.AddCommand(newReportBuildCmd())
	return cmd
}

func newReportBuildCmd() *cobra.Command {
	var format string
	var outPath string
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Render a report separating observation, inference and speculation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()
			if err := ctx.authorize(cmd.Context(), scope.CapReportGeneration, ctx.Manifest.Authorization.ProjectID); err != nil {
				return err
			}

			projectID := ctx.Manifest.Authorization.ProjectID
			artifacts, err := ctx.Store.ListArtifacts(cmd.Context(), projectID)
			if err != nil {
				return err
			}
			records, err := ctx.Store.ListFindings(cmd.Context(), projectID)
			if err != nil {
				return err
			}
			findings := make([]confidence.Finding, 0, len(records))
			for _, r := range records {
				findings = append(findings, confidence.FromRecord(r))
			}

			data := report.Data{
				Tool: "reverso", Version: version, GeneratedAt: time.Now().UTC(),
				ProjectID: projectID, Owner: ctx.Manifest.Authorization.Owner,
				Manifest: ctx.Manifest, Artifacts: artifacts, Findings: findings,
			}

			w := cmd.OutOrStdout()
			if outPath != "" {
				f, ferr := os.Create(outPath)
				if ferr != nil {
					return fmt.Errorf("creating report file: %w", ferr)
				}
				defer func() { _ = f.Close() }()
				if rerr := report.Render(f, format, data); rerr != nil {
					return rerr
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s report to %s\n", format, outPath)
				return nil
			}
			return report.Render(w, format, data)
		},
	}
	cmd.Flags().StringVar(&format, "format", "markdown", fmt.Sprintf("report format: %v", report.Formats))
	cmd.Flags().StringVar(&outPath, "out", "", "write to a file instead of stdout")
	return cmd
}
