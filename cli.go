package main

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

// writeReport runs render, writing to outPath — or stdout when outPath is
// empty. For file output it disables color (never write ANSI codes into a file)
// and treats a close failure as an error, so a truncated report is never
// reported as success. Shared by the scan, evaluate, and hunt commands.
func writeReport(outPath string, render func(io.Writer) error) error {
	if outPath == "" {
		return render(os.Stdout)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	color.NoColor = true
	if err := render(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing report file: %w", err)
	}
	return nil
}

// newJudge builds the isolated Layer 3 judge from ANTHROPIC_API_KEY, or returns
// a nil Judge when no key is set — in which case Layer 3 is skipped
// (non-blocking), not failed closed. Shared by the guard and evaluate commands.
func newJudge(model string) verify.Judge {
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		return verify.NewLLMJudge(analyzer.NewClient(apiKey, model), model)
	}
	return nil
}
