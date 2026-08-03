package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Work with the immutable audit trail",
	}
	cmd.AddCommand(newAuditVerifyCmd())
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit trail's hash chain and signatures",
		Long: "verify reads the audit public key from the workspace and checks every\n" +
			"record's hash chain and signature. Pin the audit public key externally so a\n" +
			"tamper that also rewrites the workspace key can still be detected.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !initialized(flagDir) {
				return ErrNotInitialized
			}
			pubRaw, err := readKeyFile(flagDir, auditPubName)
			if err != nil {
				return fmt.Errorf("reading audit public key: %w", err)
			}
			pub, err := scope.DecodePublicKey(string(pubRaw))
			if err != nil {
				return fmt.Errorf("decoding audit public key: %w", err)
			}
			log := evidence.OpenAuditLog(filepath.Join(work(flagDir), auditName))
			if err := log.Verify(pub); err != nil {
				return fmt.Errorf("audit trail FAILED verification: %w", err)
			}
			events, err := log.Events("")
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Audit trail VERIFIED: %d record(s), hash chain and signatures intact\n", len(events))
			allowed, denied := 0, 0
			for _, e := range events {
				if e.Decision == "allowed" {
					allowed++
				} else {
					denied++
				}
			}
			fmt.Fprintf(out, "  allowed: %d  denied: %d\n", allowed, denied)
			return nil
		},
	}
}
