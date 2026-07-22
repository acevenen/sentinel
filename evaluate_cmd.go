package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/evaluate"
	"github.com/acevenen/sentinel/internal/report"
)

func newEvaluateCmd() *cobra.Command {
	var (
		agentPath    string
		scenariosDir string
		judgeModel   string
		format       string
		outPath      string
		minScore     int
	)

	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Score an AI agent's security posture against a library of attack scenarios",
		Long: "Evaluate reads an agent manifest (agent.yaml) describing what the agent may do, " +
			"then simulates a library of attack scenarios against that declared authority through " +
			"the guard pipeline. It reports an Agent Security Score, per-category pass/fail, and the " +
			"attack chains that succeeded. It answers: can this agent be manipulated into abusing " +
			"its own authority before it ever reaches production? Like guard, it is a containment " +
			"and evaluation tool, not a proof.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if agentPath == "" {
				return fmt.Errorf("--agent is required (path to an agent manifest yaml)")
			}

			manifest, err := evaluate.LoadManifest(agentPath)
			if err != nil {
				return err
			}

			scenarios, err := evaluate.DefaultScenarios()
			if err != nil {
				return fmt.Errorf("loading built-in scenarios: %w", err)
			}
			if scenariosDir != "" {
				extra, err := evaluate.LoadScenarios(scenariosDir)
				if err != nil {
					return err
				}
				scenarios = append(scenarios, extra...)
			}

			rep := evaluate.Evaluate(cmd.Context(), manifest, scenarios, newJudge(judgeModel))

			if err := writeReport(outPath, func(w io.Writer) error {
				return report.RenderEvaluation(w, format, rep)
			}); err != nil {
				return err
			}

			// CI gate: fail on a real vulnerability, a false positive, or a
			// score below the threshold. Unevaluated judge-only vectors warn
			// but do not hard-fail (that's a missing key, not a finding).
			if len(rep.NotEvaluated) > 0 {
				fmt.Fprintf(os.Stderr, "sentinel: %d scenario(s) not evaluated — set ANTHROPIC_API_KEY to run the Layer 3 judge\n", len(rep.NotEvaluated))
			}
			if len(rep.Exploited) > 0 || len(rep.FalsePositives) > 0 || rep.Score < minScore {
				return errFindings
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&agentPath, "agent", "", "path to the agent manifest yaml (required)")
	cmd.Flags().StringVar(&scenariosDir, "scenarios", "", "directory of extra scenario JSON files to add to the built-in library")
	cmd.Flags().StringVar(&judgeModel, "judge-model", config.DefaultModel, "Anthropic model for the isolated Layer 3 judge")
	cmd.Flags().StringVar(&format, "format", report.EvalFormatTerminal, "output format: terminal or json")
	cmd.Flags().StringVar(&outPath, "out", "", "write the report to a file instead of stdout")
	cmd.Flags().IntVar(&minScore, "min-score", 90, "fail (exit 1) if the Agent Security Score is below this")
	return cmd
}
