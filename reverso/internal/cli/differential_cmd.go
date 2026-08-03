package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/differential"
	"github.com/acevenen/sentinel/reverso/internal/firmware"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newDifferentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "differential",
		Short: "Compare two firmware images, traces or configs",
	}
	cmd.AddCommand(newDifferentialCompareCmd())
	return cmd
}

func newDifferentialCompareCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "compare <old> <new>",
		Short: "Diff two firmware images and score the changes for security relevance",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()
			if err := ctx.authorize(cmd.Context(), scope.CapDifferentialAnalysis, args[0]+" vs "+args[1]); err != nil {
				return err
			}
			oldData, _, err := readCapped(args[0])
			if err != nil {
				return err
			}
			newData, _, err := readCapped(args[1])
			if err != nil {
				return err
			}
			d := differential.Compare(firmware.Inspect(args[0], oldData), firmware.Inspect(args[1], newData))
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(d)
			}
			fmt.Fprintf(out, "Differential: %s -> %s\n", args[0], args[1])
			fmt.Fprintf(out, "  entropy delta: %+.2f\n", d.EntropyDelta)
			fmt.Fprintf(out, "  relevance score: %d/100\n", d.RelevanceScore)
			for _, c := range d.ComponentChanges {
				fmt.Fprintf(out, "    [%s] %s %s -> %s\n", c.Kind, c.Name, c.OldVersion, c.NewVersion)
			}
			if d.NewKeyMarkers > 0 {
				fmt.Fprintf(out, "    +%d new key/cert markers\n", d.NewKeyMarkers)
			}
			for _, f := range d.NewInsecureFlags {
				fmt.Fprintf(out, "    + insecure flag: %s\n", f)
			}
			for _, f := range d.RemovedInsecure {
				fmt.Fprintf(out, "    - insecure flag removed: %s\n", f)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
