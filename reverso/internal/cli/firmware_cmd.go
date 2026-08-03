package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/firmware"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newFirmwareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firmware",
		Short: "Defensive firmware metadata analysis",
	}
	cmd.AddCommand(newFirmwareInspectCmd())
	return cmd
}

func newFirmwareInspectCmd() *cobra.Command {
	var asJSON bool
	var store bool
	cmd := &cobra.Command{
		Use:   "inspect <firmware>",
		Short: "Extract format, SBOM, key references and insecure-config flags (metadata only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()

			if err := ctx.authorize(cmd.Context(), scope.CapFirmwareMetadataAnalysis, args[0]); err != nil {
				return err
			}
			data, sha, err := readCapped(args[0])
			if err != nil {
				return err
			}
			report := firmware.Inspect(args[0], data)
			findings := firmware.Findings(report, evidenceRef(sha))

			if store {
				for _, f := range findings {
					if err := f.Validate(); err != nil {
						continue
					}
					if err := ctx.Store.PutFinding(cmd.Context(), f.ToRecord(ctx.Manifest.Authorization.ProjectID)); err != nil {
						return err
					}
				}
			}

			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Report   firmware.Report `json:"report"`
					Findings any             `json:"findings"`
				}{report, findings})
			}
			fmt.Fprintf(out, "Firmware: %s\n", args[0])
			fmt.Fprintf(out, "  class:   %s\n", report.Class)
			fmt.Fprintf(out, "  size:    %d bytes\n", report.SizeBytes)
			fmt.Fprintf(out, "  entropy: %.2f bits/byte\n", report.Entropy)
			fmt.Fprintf(out, "  strings: %d\n", report.StringCount)
			if len(report.SBOM) > 0 {
				fmt.Fprintln(out, "  SBOM:")
				for _, c := range report.SBOM {
					fmt.Fprintf(out, "    - %s %s\n", c.Name, c.Version)
				}
			}
			if len(report.KeyMarkers) > 0 {
				fmt.Fprintln(out, "  key material references (private material is never extracted):")
				for _, k := range report.KeyMarkers {
					redacted := ""
					if k.Redacted {
						redacted = " [redacted]"
					}
					fmt.Fprintf(out, "    - %s at offset %d%s\n", k.Kind, k.Offset, redacted)
				}
			}
			if len(report.Insecure) > 0 {
				fmt.Fprintln(out, "  insecure configuration flags:")
				for _, f := range report.Insecure {
					fmt.Fprintf(out, "    - %s: %s\n", f.ID, f.Evidence)
				}
			}
			if store && len(findings) > 0 {
				fmt.Fprintf(out, "  recorded %d finding(s) to the evidence store\n", len(findings))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&store, "store", true, "record findings in the evidence store")
	return cmd
}
