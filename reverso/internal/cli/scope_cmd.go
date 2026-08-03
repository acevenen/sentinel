package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func newScopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Create and verify signed authorization manifests",
	}
	cmd.AddCommand(newScopeInitCmd(), newScopeVerifyCmd())
	return cmd
}

func newScopeInitCmd() *cobra.Command {
	var (
		projectID string
		owner     string
		assetID   string
		assetType string
		ownership string
		permit    []string
		expiresIn time.Duration
		encrypt   bool
		force     bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a project, generate owner and audit keys, and sign a manifest",
		Long: "init creates a .reverso workspace, generates an owner signing key (the trust\n" +
			"anchor) and an audit signing key, builds an authorization manifest from the\n" +
			"provided flags, signs it, and records it in the immutable evidence store.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := flagDir
			if initialized(dir) && !force {
				return fmt.Errorf("a REVerso project already exists in %s (use --force to reinitialize)", work(dir))
			}
			if err := os.MkdirAll(work(dir), 0o700); err != nil {
				return fmt.Errorf("creating workspace: %w", err)
			}

			at := scope.AssetType(assetType)
			caps := make([]scope.Capability, 0, len(permit))
			for _, p := range permit {
				caps = append(caps, scope.Capability(strings.TrimSpace(p)))
			}

			manifest := &scope.Manifest{Authorization: scope.Authorization{
				ProjectID: projectID,
				Owner:     owner,
				Target: scope.Target{
					AssetID:           assetID,
					AssetType:         at,
					OwnershipEvidence: ownership,
				},
				Permitted:  caps,
				Prohibited: scope.PermanentlyProhibited(),
				ExpiresAt:  time.Now().Add(expiresIn).UTC().Format(time.RFC3339),
			}}
			if err := manifest.Validate(); err != nil {
				return fmt.Errorf("manifest is invalid: %w", err)
			}

			// Generate owner (trust anchor) and audit keys.
			ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generating owner key: %w", err)
			}
			auditPub, auditPriv, err := newAuditKeypair()
			if err != nil {
				return fmt.Errorf("generating audit key: %w", err)
			}

			if err := manifest.Sign(ownerPriv); err != nil {
				return fmt.Errorf("signing manifest: %w", err)
			}
			if err := manifest.VerifySignature([]ed25519.PublicKey{ownerPub}); err != nil {
				return fmt.Errorf("verifying freshly signed manifest: %w", err)
			}

			// Persist keys with owner-only permissions.
			if err := writeKey(dir, ownerKeyName, []byte(scope.EncodePrivateKey(ownerPriv)), 0o600); err != nil {
				return err
			}
			if err := writeKey(dir, ownerPubName, []byte(scope.EncodePublicKey(ownerPub)), 0o644); err != nil {
				return err
			}
			if err := writeKey(dir, auditKeyName, []byte(scope.EncodePrivateKey(auditPriv)), 0o600); err != nil {
				return err
			}
			if err := writeKey(dir, auditPubName, []byte(scope.EncodePublicKey(auditPub)), 0o644); err != nil {
				return err
			}

			// Encryption salt, if requested.
			if encrypt {
				if os.Getenv(passphraseEnv) == "" {
					return fmt.Errorf("--encrypt requires %s to be set", passphraseEnv)
				}
				salt := make([]byte, 16)
				if _, err := rand.Read(salt); err != nil {
					return fmt.Errorf("generating salt: %w", err)
				}
				if err := os.WriteFile(filepath.Join(work(dir), saltName), salt, 0o600); err != nil {
					return err
				}
			}

			data, err := manifest.Marshal()
			if err != nil {
				return err
			}
			if err := os.WriteFile(manifestPath(dir), data, 0o600); err != nil {
				return fmt.Errorf("writing manifest: %w", err)
			}
			if err := writeConfig(dir, workConfig{ProjectID: projectID, Encrypted: encrypt}); err != nil {
				return err
			}

			// Record the manifest and an audit entry.
			store, err := evidence.Open(filepath.Join(work(dir), dbName))
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			if err := store.EnsureProject(cmd.Context(), projectID, owner); err != nil {
				return err
			}
			if err := store.PutManifestRecord(cmd.Context(), evidence.ManifestRecord{
				ProjectID: projectID, AssetID: assetID, AssetType: assetType,
				OwnershipEvidence: ownership, Permitted: permit,
				Prohibited: capsToStrings(scope.PermanentlyProhibited()),
				ExpiresAt:  manifest.Authorization.ExpiresAt,
				Signature:  manifest.Authorization.Signature, SignerKey: manifest.SignerKey,
				RecordedAt: time.Now().UTC(),
			}); err != nil {
				return err
			}
			audit := evidence.NewAuditLog(filepath.Join(work(dir), auditName), auditPriv)
			_ = audit.Record(cmd.Context(), evidence.Event{
				ProjectID: projectID, Actor: flagActor, Capability: string(scope.CapScopeManagement),
				Target: assetID, Decision: "allowed", Reason: "scope initialized",
				Detail: "manifest signed and recorded",
			})

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Initialized REVerso project %q in %s\n", projectID, work(dir))
			fmt.Fprintf(out, "Owner public key (trust anchor): %s\n", scope.EncodePublicKey(ownerPub))
			fmt.Fprintf(out, "Audit public key (pin this externally to detect tampering):\n  %s\n", scope.EncodePublicKey(auditPub))
			fmt.Fprintf(out, "Manifest: %s\n", manifestPath(dir))
			if encrypt {
				fmt.Fprintln(out, "Evidence blobs are ENCRYPTED at rest with your passphrase.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "project identifier (required)")
	cmd.Flags().StringVar(&owner, "owner", "", "owner identity (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "target asset identifier (required)")
	cmd.Flags().StringVar(&assetType, "asset-type", string(scope.AssetFirmwareImage),
		"asset type: detached_lab_hardware|firmware_image|passive_capture|simulator")
	cmd.Flags().StringVar(&ownership, "ownership-evidence", "", "evidence of ownership or authorization (required)")
	cmd.Flags().StringSliceVar(&permit, "permit", []string{
		string(scope.CapArtifactIngestion),
		string(scope.CapFirmwareMetadataAnalysis),
		string(scope.CapReportGeneration),
	}, "permitted capabilities")
	cmd.Flags().DurationVar(&expiresIn, "expires-in", 720*time.Hour, "manifest lifetime (e.g. 720h)")
	cmd.Flags().BoolVar(&encrypt, "encrypt", false, fmt.Sprintf("encrypt evidence blobs at rest (requires %s)", passphraseEnv))
	cmd.Flags().BoolVar(&force, "force", false, "reinitialize even if a project already exists")
	_ = cmd.MarkFlagRequired("project-id")
	_ = cmd.MarkFlagRequired("owner")
	_ = cmd.MarkFlagRequired("asset-id")
	_ = cmd.MarkFlagRequired("ownership-evidence")
	return cmd
}

func newScopeVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify [manifest.yaml]",
		Short: "Validate a manifest, verify its signature, and check expiry",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := manifestPath(flagDir)
			if len(args) == 1 {
				path = args[0]
			}
			manifest, err := scope.Load(path)
			if err != nil {
				return err
			}
			if err := manifest.Validate(); err != nil {
				return fmt.Errorf("invalid: %w", err)
			}

			out := cmd.OutOrStdout()
			// If an owner public key is present in the workspace, use it as the
			// trust anchor; otherwise report the self-consistent signer for
			// trust-on-first-use pinning.
			var trusted []ed25519.PublicKey
			if raw, rerr := readKeyFile(flagDir, ownerPubName); rerr == nil {
				if pub, perr := scope.DecodePublicKey(string(raw)); perr == nil {
					trusted = []ed25519.PublicKey{pub}
				}
			}
			if err := manifest.VerifySignature(trusted); err != nil {
				return fmt.Errorf("signature: %w", err)
			}

			expired := manifest.Expired(time.Now())
			fmt.Fprintf(out, "Manifest %s\n", path)
			fmt.Fprintf(out, "  project: %s\n", manifest.Authorization.ProjectID)
			fmt.Fprintf(out, "  asset:   %s (%s)\n", manifest.Authorization.Target.AssetID, manifest.Authorization.Target.AssetType)
			fmt.Fprintf(out, "  signer:  %s\n", manifest.SignerKey)
			fmt.Fprintf(out, "  expires: %s\n", manifest.Authorization.ExpiresAt)
			if expired {
				return fmt.Errorf("manifest is EXPIRED")
			}
			if len(trusted) == 0 {
				fmt.Fprintln(out, "  note: no owner trust anchor found; signer verified on a trust-on-first-use basis")
			}
			fmt.Fprintln(out, "  status:  VALID and signed")
			return nil
		},
	}
}

func capsToStrings(caps []scope.Capability) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = string(c)
	}
	return out
}
