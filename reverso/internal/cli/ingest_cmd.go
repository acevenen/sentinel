package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/ingest"
)

func newIngestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ingest <artifact>",
		Short: "Hash and store an owner-supplied artifact in the immutable evidence store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()

			ing := &ingest.Ingestor{
				Policy: ctx.Policy,
				Store:  ctx.Store,
				Blobs:  ctx.Blobs,
				Audit:  ctx.Audit,
				Actor:  ctx.Actor,
			}
			rec, err := ing.Ingest(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Ingested %s\n", rec.OriginalName)
			fmt.Fprintf(out, "  sha256: %s\n", rec.SHA256)
			fmt.Fprintf(out, "  type:   %s (%s)\n", rec.DetectedType, rec.MediaType)
			fmt.Fprintf(out, "  size:   %d bytes\n", rec.SizeBytes)
			if rec.Encrypted {
				fmt.Fprintln(out, "  stored encrypted at rest")
			}
			return nil
		},
	}
}
