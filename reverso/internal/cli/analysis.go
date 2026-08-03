package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

// maxAnalysisBytes caps how much of a file an analysis command reads into
// memory, treating every artifact as hostile and bounding resource use.
const maxAnalysisBytes int64 = 512 << 20

// assetType is the manifest's target asset type.
func (c *Context) assetType() scope.AssetType {
	return c.Manifest.Authorization.Target.AssetType
}

// authorize checks a capability, writes the decision to the audit trail, and
// returns the policy error (nil when allowed). Both allowed and denied
// decisions are audited.
func (c *Context) authorize(ctx context.Context, cap scope.Capability, target string) error {
	dec, err := c.Policy.Authorize(ctx, scope.Action{
		Capability: cap,
		AssetType:  c.assetType(),
		Target:     target,
	})
	decision, reason := "allowed", "authorized"
	if err != nil {
		decision, reason = "denied", dec.Reason
	}
	if aerr := c.Audit.Record(ctx, evidence.Event{
		ProjectID:  c.Manifest.Authorization.ProjectID,
		Actor:      c.Actor,
		Capability: string(cap),
		Target:     target,
		Decision:   decision,
		Reason:     reason,
	}); aerr != nil {
		return fmt.Errorf("audit record failed: %w", aerr)
	}
	return err
}

// readCapped reads up to maxAnalysisBytes of path and returns the bytes and
// their SHA-256, without modifying the file. It errors if the file exceeds the
// cap rather than silently truncating.
func readCapped(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAnalysisBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", path, err)
	}
	if int64(len(data)) > maxAnalysisBytes {
		return nil, "", fmt.Errorf("%s exceeds the %d byte analysis cap", path, maxAnalysisBytes)
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// evidenceRef returns the sha256: reference form used in findings.
func evidenceRef(sha string) string { return "sha256:" + sha }
