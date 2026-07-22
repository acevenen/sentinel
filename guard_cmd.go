package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/guard"
	"github.com/acevenen/sentinel/internal/guard/detect"
	"github.com/acevenen/sentinel/internal/guard/intent"
	"github.com/acevenen/sentinel/internal/report"
)

func newGuardCmd() *cobra.Command {
	var (
		intentPath string
		streamPath string
		judgeModel string
		reportPath string
	)

	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Runtime guard: inspect tool outputs and verify actions against declared intent",
		Long: "Guard reads a declared intent and a stream of tool outputs / proposed actions " +
			"(JSONL), runs five injection/exfiltration detectors over every tool output, and " +
			"verifies every consequential action against the intent through four layers " +
			"(declare, static match, isolated LLM judge, session drift). It is a defensive, " +
			"zero-trust containment layer — not a safety guarantee.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if intentPath == "" || streamPath == "" {
				return fmt.Errorf("--intent and --stream are both required")
			}

			declared, err := intent.Load(intentPath)
			if err != nil {
				return err
			}
			events, err := readStream(streamPath)
			if err != nil {
				return err
			}

			// Layer 3 judge: reuse Sentinel's analyzer client when an API key is
			// present. Without a key, Layer 3 is skipped (non-blocking) so the
			// deterministic layers still run offline.
			judge := newJudge(judgeModel)

			session := guard.Run(cmd.Context(), events, guard.Options{
				Intent:    declared,
				Detectors: detect.All(),
				Judge:     judge,
			})

			report.RenderGuardTable(os.Stdout, session, judge != nil)

			if reportPath != "" {
				if err := writeReport(reportPath, func(w io.Writer) error {
					return report.WriteGuardSARIF(w, streamPath, session, version)
				}); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "sentinel: wrote SARIF report to %s\n", reportPath)
			}

			if session.Blocked {
				return errFindings
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&intentPath, "intent", "", "path to the declared-intent JSON file (required)")
	cmd.Flags().StringVar(&streamPath, "stream", "", "path to the JSONL stream of tool outputs / actions (required)")
	cmd.Flags().StringVar(&judgeModel, "judge-model", config.DefaultModel, "Anthropic model for the isolated Layer 3 judge")
	cmd.Flags().StringVar(&reportPath, "report", "", "write a SARIF report to this file")
	return cmd
}

// readStream parses a JSONL file into guard events, skipping blank lines.
func readStream(path string) ([]guard.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening stream: %w", err)
	}
	defer func() { _ = f.Close() }()

	var events []guard.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var ev guard.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, fmt.Errorf("stream line %d is not valid JSON: %w", line, err)
		}
		if ev.Seq == 0 {
			ev.Seq = line
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading stream: %w", err)
	}
	return events, nil
}
