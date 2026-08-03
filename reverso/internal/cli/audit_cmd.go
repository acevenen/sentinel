package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

// auditPubkeyEnv lets an operator supply an externally-pinned audit public key
// so verification does not rely solely on the copy inside the writable
// workspace (which an attacker who can rewrite the log could also replace).
const auditPubkeyEnv = "REVERSO_AUDIT_PUBKEY"

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Work with the immutable audit trail",
	}
	cmd.AddCommand(newAuditVerifyCmd())
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var (
		pubkeyFlag string
		anchorPath string
		saveAnchor string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit trail's hash chain and signatures",
		Long: "verify checks every record's hash chain and signature. The hash chain\n" +
			"detects edits, reordering and non-trailing deletions. Trailing truncation\n" +
			"(deleting the newest records) cannot be detected from the log alone, so pin\n" +
			"the head externally with --save-anchor and later check it with --anchor. For\n" +
			"the same reason, prefer an externally-pinned audit public key via " + auditPubkeyEnv + "\n" +
			"or --audit-pubkey rather than the copy in the writable workspace.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !initialized(flagDir) {
				return ErrNotInitialized
			}
			out := cmd.OutOrStdout()

			pub, pinned, err := resolveAuditPubkey(pubkeyFlag)
			if err != nil {
				return err
			}
			if !pinned {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: using the audit public key from the workspace; pin it via %s or --audit-pubkey to detect a full re-sign forgery\n",
					auditPubkeyEnv)
			}

			log := evidence.OpenAuditLog(filepath.Join(work(flagDir), auditName))

			// Verify against a saved anchor if provided; this detects trailing
			// truncation below the anchored point.
			if anchorPath != "" {
				anchor, aerr := loadAnchor(anchorPath)
				if aerr != nil {
					return aerr
				}
				if cerr := log.CheckAnchor(pub, anchor); cerr != nil {
					return fmt.Errorf("audit trail FAILED verification: %w", cerr)
				}
			}

			head, err := log.VerifiedHead(pub)
			if err != nil {
				return fmt.Errorf("audit trail FAILED verification: %w", err)
			}

			events, err := log.Events("")
			if err != nil {
				return err
			}
			allowed, denied := 0, 0
			for _, e := range events {
				if e.Decision == "allowed" {
					allowed++
				} else {
					denied++
				}
			}
			fmt.Fprintf(out, "Audit trail VERIFIED: %d record(s), hash chain and signatures intact\n", head.Count)
			fmt.Fprintf(out, "  allowed: %d  denied: %d\n", allowed, denied)
			fmt.Fprintf(out, "  head: %s\n", shortHash(head.HeadHash))
			if anchorPath == "" {
				fmt.Fprintln(out, "  note: trailing truncation is NOT detectable without --anchor; save one with --save-anchor")
			} else {
				fmt.Fprintln(out, "  anchor: matched (no trailing truncation below the anchored point)")
			}

			if saveAnchor != "" {
				if err := saveAnchorFile(saveAnchor, head); err != nil {
					return err
				}
				fmt.Fprintf(out, "  saved anchor to %s (store it off this host)\n", saveAnchor)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pubkeyFlag, "audit-pubkey", "", "externally-pinned base64 audit public key (overrides the workspace copy)")
	cmd.Flags().StringVar(&anchorPath, "anchor", "", "verify against a previously saved head anchor to detect trailing truncation")
	cmd.Flags().StringVar(&saveAnchor, "save-anchor", "", "write the current head to this file for external pinning")
	return cmd
}

// resolveAuditPubkey returns the audit public key to verify against. It prefers,
// in order: the --audit-pubkey flag, the REVERSO_AUDIT_PUBKEY env, then the
// workspace copy. pinned is true for the first two (externally supplied).
func resolveAuditPubkey(flagVal string) (pub []byte, pinned bool, err error) {
	enc := flagVal
	if enc == "" {
		enc = os.Getenv(auditPubkeyEnv)
	}
	if enc != "" {
		key, derr := scope.DecodePublicKey(enc)
		if derr != nil {
			return nil, false, fmt.Errorf("decoding pinned audit public key: %w", derr)
		}
		return key, true, nil
	}
	raw, rerr := readKeyFile(flagDir, auditPubName)
	if rerr != nil {
		return nil, false, fmt.Errorf("reading audit public key: %w", rerr)
	}
	key, derr := scope.DecodePublicKey(string(raw))
	if derr != nil {
		return nil, false, fmt.Errorf("decoding audit public key: %w", derr)
	}
	return key, false, nil
}

func loadAnchor(path string) (evidence.Head, error) {
	var h evidence.Head
	data, err := os.ReadFile(path)
	if err != nil {
		return h, fmt.Errorf("reading anchor: %w", err)
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return h, fmt.Errorf("parsing anchor: %w", err)
	}
	return h, nil
}

func saveAnchorFile(path string, head evidence.Head) error {
	data, err := json.MarshalIndent(head, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	if h == "" {
		return "(empty)"
	}
	return h
}
