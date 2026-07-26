package main

import (
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/bounty"
	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/ctf"
	"github.com/acevenen/sentinel/internal/engagement"
)

func newCTFCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ctf",
		Short: "Create policy-locked CTF engagements and regression scorecards",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newCTFStartCmd(), newCTFScoreCmd())
	return cmd
}

func newCTFStartCmd() *cobra.Command {
	var (
		manifestPath string
		challengeID  string
		engagementID string
		operator     string
		attestRules  bool
		out          string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Create an engagement from a reviewed CTF challenge policy",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			manifest, err := ctf.LoadManifest(manifestPath)
			if err != nil {
				return err
			}
			record, err := manifest.Engagement(challengeID, operator, attestRules)
			if err != nil {
				return err
			}
			if engagementID != "" {
				record.ID = engagementID
			}
			store := engagement.FileStore{Dir: config.LoadOperational().EngagementDir}
			if err := store.Save(record); err != nil {
				return err
			}
			saved, err := store.Get(record.ID)
			if err != nil {
				return err
			}
			return writeJSON(out, saved)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "operator-supplied CTF policy YAML/JSON (required)")
	cmd.Flags().StringVar(&challengeID, "challenge", "", "challenge id from the manifest (required)")
	cmd.Flags().StringVar(&engagementID, "engagement", "", "optional portable engagement id override")
	cmd.Flags().StringVar(&operator, "operator", defaultOperator(), "accountable operator identity")
	cmd.Flags().BoolVar(&attestRules, "attest-rules", false, "attest that the platform's current rules were reviewed")
	cmd.Flags().StringVar(&out, "out", "", "write structured output to a file instead of stdout")
	_ = cmd.MarkFlagRequired("manifest")
	_ = cmd.MarkFlagRequired("challenge")
	return cmd
}

func newCTFScoreCmd() *cobra.Command {
	var (
		manifestPath string
		runPath      string
		historyPath  string
		noHistory    bool
		out          string
	)
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Compute and persist a CTF methodology regression scorecard",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			manifest, err := ctf.LoadManifest(manifestPath)
			if err != nil {
				return err
			}
			run, err := ctf.LoadRunRecord(runPath)
			if err != nil {
				return err
			}
			card, err := ctf.Score(manifest, run)
			if err != nil {
				return err
			}
			if !noHistory {
				if historyPath == "" {
					historyPath = filepath.Join(config.LoadOperational().StateDir, "ctf-scorecards.jsonl")
				}
				if err := ctf.AppendHistory(historyPath, card); err != nil {
					return err
				}
			}
			return writeJSON(out, card)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "operator-supplied CTF policy YAML/JSON (required)")
	cmd.Flags().StringVar(&runPath, "run", "", "operator-confirmed CTF run YAML/JSON (required)")
	cmd.Flags().StringVar(&historyPath, "history", "", "scorecard JSONL history (defaults under SENTINEL_STATE_DIR)")
	cmd.Flags().BoolVar(&noHistory, "no-history", false, "do not append the scorecard history")
	cmd.Flags().StringVar(&out, "out", "", "write structured output to a file instead of stdout")
	_ = cmd.MarkFlagRequired("manifest")
	_ = cmd.MarkFlagRequired("run")
	return cmd
}

func newBountyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bounty",
		Short: "Import an enrolled bounty program as a policy-locked engagement",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newBountyImportCmd())
	return cmd
}

func newBountyImportCmd() *cobra.Command {
	var (
		programPath  string
		engagementID string
		operator     string
		attestPolicy bool
		out          string
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import current bounty scope, deny rules, and automation limits",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if engagementID == "" {
				return errors.New("--engagement is required")
			}
			program, err := bounty.Load(programPath)
			if err != nil {
				return err
			}
			record, err := program.Engagement(engagementID, operator, attestPolicy)
			if err != nil {
				return err
			}
			store := engagement.FileStore{Dir: config.LoadOperational().EngagementDir}
			if err := store.Save(record); err != nil {
				return err
			}
			saved, err := store.Get(record.ID)
			if err != nil {
				return err
			}
			return writeJSON(out, saved)
		},
	}
	cmd.Flags().StringVar(&programPath, "program", "", "operator-supplied bounty policy YAML/JSON (required)")
	cmd.Flags().StringVar(&engagementID, "engagement", "", "portable engagement id (required)")
	cmd.Flags().StringVar(&operator, "operator", defaultOperator(), "accountable enrolled researcher")
	cmd.Flags().BoolVar(&attestPolicy, "attest-policy", false, "attest current enrollment and policy review")
	cmd.Flags().StringVar(&out, "out", "", "write structured output to a file instead of stdout")
	_ = cmd.MarkFlagRequired("program")
	return cmd
}
