package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/scope"
	"github.com/acevenen/sentinel/reverso/internal/simulator"
)

func newSimulateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Software-only replay of sanitized traces",
	}
	cmd.AddCommand(newSimulateReplayCmd())
	return cmd
}

func newSimulateReplayCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "replay <sanitized-trace.json>",
		Short: "Replay a sanitized trace through a software-only model (never emits to hardware)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()
			if err := ctx.authorize(cmd.Context(), scope.CapSimulation, args[0]); err != nil {
				return err
			}
			data, _, err := readCapped(args[0])
			if err != nil {
				return err
			}
			trace, err := simulator.LoadTrace(data)
			if err != nil {
				return err
			}
			res := simulator.Replay(trace)
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Fprintf(out, "Replayed trace %q (software-only, emitted=%v)\n", res.Name, res.Emitted)
			fmt.Fprintf(out, "  messages: %d\n", res.Messages)
			for _, k := range res.SortedKinds() {
				fmt.Fprintf(out, "    %s: %d\n", k, res.KindCounts[k])
			}
			if len(res.ParseErrors) > 0 {
				fmt.Fprintln(out, "  parse errors:")
				for _, e := range res.ParseErrors {
					fmt.Fprintf(out, "    - %s\n", e)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
