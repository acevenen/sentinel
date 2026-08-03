package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/ingest"
	"github.com/acevenen/sentinel/reverso/internal/protocol"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newProtocolCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "protocol",
		Short: "Passive protocol analysis of owner-provided captures",
	}
	cmd.AddCommand(newProtocolInferCmd())
	return cmd
}

func newProtocolInferCmd() *cobra.Command {
	var profile string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "infer <capture>",
		Short: "Passively summarize a capture (never transmits)",
		Long: "infer reads an owner-provided capture and summarizes it. It is strictly\n" +
			"passive: it opens no socket and sends no frame. Message clustering and field\n" +
			"inference build on this summary in a later milestone.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()
			if err := ctx.authorize(cmd.Context(), scope.CapPassiveCaptureAnalysis, args[0]); err != nil {
				return err
			}
			data, _, err := readCapped(args[0])
			if err != nil {
				return err
			}
			det := ingest.Detect(args[0], data)
			out := cmd.OutOrStdout()

			switch det.Class {
			case ingest.ClassPCAP:
				s, err := protocol.SummarizePCAP(data)
				if err != nil {
					return err
				}
				if asJSON {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(s)
				}
				fmt.Fprintf(out, "Capture: %s (classic pcap, %s-endian)\n", args[0], s.ByteOrder)
				fmt.Fprintf(out, "  link type: %d  snaplen: %d\n", s.LinkType, s.SnapLen)
				fmt.Fprintf(out, "  packets:   %d  bytes: %d\n", s.Packets, s.TotalBytes)
				if s.Packets > 0 {
					fmt.Fprintf(out, "  span:      %s -> %s (%s)\n", s.FirstTime.Format("15:04:05"), s.LastTime.Format("15:04:05"), s.Duration)
				}
			case ingest.ClassPCAPNG:
				fmt.Fprintf(out, "Capture: %s (pcapng). Classic-pcap summarization is available now;\n"+
					"pcapng block parsing and message clustering land in Milestone 2.\n", args[0])
			case ingest.ClassCSV:
				if profile == "automotive-passive" {
					fmt.Fprintf(out, "Capture: %s (CSV, automotive-passive profile).\n"+
						"CSV bus-capture field clustering lands in Milestone 2/3; the file is\n"+
						"recognized and treated strictly passively.\n", args[0])
				} else {
					fmt.Fprintf(out, "Capture: %s (CSV). Pass --profile automotive-passive for bus captures.\n", args[0])
				}
			default:
				fmt.Fprintf(out, "Capture: %s classified as %s; no passive protocol summarizer applies yet.\n", args[0], det.Class)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "capture profile, e.g. automotive-passive")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
