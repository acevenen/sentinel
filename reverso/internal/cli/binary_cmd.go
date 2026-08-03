package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/binmap"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newBinaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "binary",
		Short: "Defensive binary analysis",
	}
	cmd.AddCommand(newBinaryMapCmd())
	return cmd
}

func newBinaryMapCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "map <binary>",
		Short: "Inventory ELF sections and locate crypto and trust-decision functions",
		Long:  "map is read-only: it locates where verification happens; it never patches or disables it.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()
			if err := ctx.authorize(cmd.Context(), scope.CapBinaryAnalysis, args[0]); err != nil {
				return err
			}
			data, _, err := readCapped(args[0])
			if err != nil {
				return err
			}
			report, err := binmap.Analyze(data)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(out, "Binary: %s\n", args[0])
			fmt.Fprintf(out, "  class: %s  machine: %s  type: %s\n", report.Class, report.Machine, report.Type)
			fmt.Fprintf(out, "  sections: %d  symbols: %d  imported: %d  stripped: %v\n",
				len(report.Sections), report.SymbolCount, report.ImportedCount, report.Stripped)
			printList(out, "crypto functions", report.CryptoSymbols)
			printList(out, "trust-decision functions", report.TrustSymbols)
			printList(out, "parser functions", report.ParserSymbols)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func printList(out interface{ Write([]byte) (int, error) }, heading string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(out, "  %s:\n", heading)
	for _, s := range items {
		fmt.Fprintf(out, "    - %s\n", s)
	}
}
