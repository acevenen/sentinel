package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/reverso/internal/firmware"
	"github.com/acevenen/sentinel/reverso/internal/scope"
	"github.com/acevenen/sentinel/reverso/internal/trustmap"
)

func newTrustmapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trustmap",
		Short: "Map roots of trust, keys and authorization boundaries",
	}
	cmd.AddCommand(newTrustmapBuildCmd())
	return cmd
}

func newTrustmapBuildCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a trust graph from the project's ingested evidence",
		Long: "build reconstructs a trust graph from key and certificate references found\n" +
			"in the project's ingested artifacts. Private key material is never extracted;\n" +
			"only its presence and location are recorded.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loadContext(flagDir, flagActor)
			if err != nil {
				return err
			}
			defer ctx.Close()
			if err := ctx.authorize(cmd.Context(), scope.CapTrustMapping, ctx.Manifest.Authorization.ProjectID); err != nil {
				return err
			}

			projectID := ctx.Manifest.Authorization.ProjectID
			g := trustmap.New(projectID)
			rootID := "device_root_of_trust"
			_ = g.AddNode(trustmap.Node{ID: rootID, Kind: trustmap.KindRootOfTrust, Label: "Device root of trust"})

			artifacts, err := ctx.Store.ListArtifacts(cmd.Context(), projectID)
			if err != nil {
				return err
			}
			for _, a := range artifacts {
				data, gerr := ctx.Blobs.Get(a.SHA256)
				if gerr != nil {
					// A missing or tampered blob is surfaced, not silently skipped.
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: cannot read blob %s: %v\n", a.SHA256[:12], gerr)
					continue
				}
				addArtifactToGraph(g, rootID, a.OriginalName, a.SHA256, firmware.Inspect(a.OriginalName, data))
			}

			out := cmd.OutOrStdout()
			switch format {
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(g)
			case "", "dot":
				fmt.Fprint(out, g.DOT())
			default:
				return fmt.Errorf("unknown format %q (want dot or json)", format)
			}
			roots := g.Roots()
			fmt.Fprintf(cmd.ErrOrStderr(), "trust graph: %d nodes, %d roots\n", len(g.Nodes), len(roots))
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "dot", "output format: dot|json")
	return cmd
}

func addArtifactToGraph(g *trustmap.Graph, rootID, name, sha string, r firmware.Report) {
	short := sha
	if len(short) > 8 {
		short = short[:8]
	}
	artNode := "artifact:" + short
	if err := g.AddNode(trustmap.Node{ID: artNode, Kind: trustmap.KindService, Label: name}); err != nil {
		return
	}
	_ = g.AddEdge(trustmap.Edge{From: rootID, To: artNode, Kind: trustmap.EdgeVerifies})

	for i, km := range r.KeyMarkers {
		id := fmt.Sprintf("%s:key%d", artNode, i)
		if km.IsPrivate {
			// Record presence only; never a public key node holding material.
			_ = g.AddNode(trustmap.Node{
				ID: id, Kind: trustmap.KindBoundary, Label: "embedded private key (not extracted)",
				Notes: []string{fmt.Sprintf("private key material referenced at offset %d; contents not read", km.Offset)},
			})
			_ = g.AddEdge(trustmap.Edge{From: artNode, To: id, Kind: trustmap.EdgeReferences})
			continue
		}
		kind := trustmap.KindPublicKey
		if km.Kind == "certificate" {
			kind = trustmap.KindCertificate
		}
		_ = g.AddNode(trustmap.Node{
			ID: id, Kind: kind, Label: km.Kind,
			KeyRef: &trustmap.KeyReference{
				Label: km.Kind, Location: fmt.Sprintf("%s@%d", name, km.Offset),
				EvidenceID: evidenceRef(sha), IsPublic: true,
			},
		})
		_ = g.AddEdge(trustmap.Edge{From: artNode, To: id, Kind: trustmap.EdgeReferences})
	}
}
