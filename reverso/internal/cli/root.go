// Package cli implements the reverso command-line interface. Every command that
// touches an artifact or target routes through the authorization policy engine
// and writes to the immutable audit trail; commands fail closed when scope is
// missing, expired, unsigned, or ambiguous.
package cli

import (
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

// global flags shared by all commands.
var (
	flagDir   string
	flagActor string
)

func defaultActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "operator"
}

// NewRootCmd builds the reverso command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "reverso",
		Short: "Authorization-first defensive reverse engineering for owned hardware",
		Long: "REVerso helps a researcher understand software, firmware, protocols and\n" +
			"trust boundaries in systems they own or are explicitly authorized to assess.\n" +
			"It is observation-first, fails closed without a signed authorization manifest,\n" +
			"and refuses to become an exploit autopilot.",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&flagDir, "dir", ".", "project directory containing the .reverso workspace")
	root.PersistentFlags().StringVar(&flagActor, "actor", defaultActor(), "operator identity recorded in the audit trail")

	root.AddCommand(
		newScopeCmd(),
		newIngestCmd(),
		newFirmwareCmd(),
		newBinaryCmd(),
		newProtocolCmd(),
		newTrustmapCmd(),
		newDifferentialCmd(),
		newSimulateCmd(),
		newReportCmd(),
		newAuditCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the reverso version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("reverso %s\n", version)
		},
	}
}
