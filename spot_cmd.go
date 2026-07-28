package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/knowledge"
	"github.com/acevenen/sentinel/internal/spotter"
)

// newSpotCmd builds `sentinel spot`: identify a device the operator owns from
// what they can see and passively learn about it, then report what is known
// against it and what to do about it.
//
// Every observation is supplied by the operator. The command performs no
// network activity at all, which is why it needs no --authorized flag: it is
// the offline half of Spotter. Anything that puts a packet on the wire is a
// separate active command gated by internal/authz.
func newSpotCmd() *cobra.Command {
	var (
		observations []string
		firmware     string
		mac          string
		address      string
		exposure     string
		defaultCreds bool
		unenrolled   bool
		format       string
		out          string
	)

	cmd := &cobra.Command{
		Use:   "spot",
		Short: "Identify a device you own and report what is known against it",
		Long: strings.TrimSpace(`
Identify a device from operator observations and report its known weaknesses
with a ranked, plain-language plan for fixing them.

Observations are supplied as kind=value pairs and fused into one
confidence-scored identity: a claim supported by only one class of evidence can
never reach "confirmed", so a single sensor never produces a confident answer.

Observation kinds:
  logo, label-model, form-factor    what you can see on the device
  mac-oui                           its hardware address (any separator form)
  http-server, http-realm, tls-cn   banners you already have
  upnp-model                        its UPnP/SSDP descriptor

This command is entirely offline. It sends no packets and makes no network
call, so it runs air-gapped.`),
		Example: strings.TrimSpace(`
  # A camera you own, identified from its label and its MAC
  sentinel spot --observe logo=hikvision --observe mac-oui=44:19:B6:11:22:33 \
      --exposure lan

  # Same device, exposed to the internet, emitting the glasses HUD contract
  sentinel spot --observe logo=hikvision --observe http-server=Hikvision-Webs \
      --exposure internet --format hud`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			parsed, err := parseObservations(observations)
			if err != nil {
				return err
			}
			if mac != "" {
				parsed = append(parsed, spotter.Observation{
					Kind: spotter.SignalMACOUI, Value: mac, Quality: 1, Sensor: "operator",
				})
			}
			if len(parsed) == 0 {
				return fmt.Errorf("supply at least one --observe kind=value (or --mac)")
			}

			exp, err := parseExposure(exposure)
			if err != nil {
				return err
			}

			identity := spotter.Fuse(parsed, knowledge.DeviceFingerprints())
			device := spotter.Device{
				Identity:     identity,
				MAC:          mac,
				Address:      address,
				Firmware:     firmware,
				Exposure:     exp,
				DefaultCreds: defaultCreds,
			}
			assessment := spotter.Assess(device, knowledge.DeviceAdvisories())

			return writeReport(out, func(w io.Writer) error {
				switch format {
				case "json":
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					return enc.Encode(assessment)
				case "hud":
					card := spotter.ToHUD(assessment, !unenrolled)
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					return enc.Encode(card)
				case "terminal", "":
					return renderSpotTerminal(w, assessment, !unenrolled)
				default:
					return fmt.Errorf("unknown format %q: use terminal, json, or hud", format)
				}
			})
		},
	}

	cmd.Flags().StringArrayVar(&observations, "observe", nil,
		"observation as kind=value (repeatable); see --help for kinds")
	cmd.Flags().StringVar(&mac, "mac", "", "device hardware address, in any separator form")
	cmd.Flags().StringVar(&address, "address", "", "device IP address, recorded for the report only")
	cmd.Flags().StringVar(&firmware, "firmware", "", "firmware version, if you know it (improves accuracy)")
	cmd.Flags().StringVar(&exposure, "exposure", "unknown",
		"how reachable the device is: internet|lan|isolated|unknown")
	cmd.Flags().BoolVar(&defaultCreds, "default-credentials-suspected", false,
		"you have not changed the device's factory password")
	cmd.Flags().BoolVar(&unenrolled, "unenrolled", false,
		"treat the device as one you have not claimed; withholds the assessment")
	cmd.Flags().StringVar(&format, "format", "terminal", "output format: terminal|json|hud")
	cmd.Flags().StringVar(&out, "out", "", "write the report to a file instead of stdout")
	return cmd
}

// parseObservations turns repeated kind=value flags into observations.
func parseObservations(raw []string) ([]spotter.Observation, error) {
	valid := map[string]spotter.SignalKind{
		"logo":        spotter.SignalLogo,
		"label-model": spotter.SignalLabelModel,
		"form-factor": spotter.SignalFormFactor,
		"mac-oui":     spotter.SignalMACOUI,
		"http-server": spotter.SignalHTTPServer,
		"http-realm":  spotter.SignalHTTPRealm,
		"tls-cn":      spotter.SignalTLSCN,
		"upnp-model":  spotter.SignalUPnPModel,
		"firmware":    spotter.SignalFirmware,
	}
	var out []spotter.Observation
	for _, entry := range raw {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("observation %q must be kind=value", entry)
		}
		kind, ok := valid[strings.ToLower(strings.TrimSpace(key))]
		if !ok {
			kinds := make([]string, 0, len(valid))
			for name := range valid {
				kinds = append(kinds, name)
			}
			sort.Strings(kinds)
			return nil, fmt.Errorf("unknown observation kind %q; valid kinds: %s",
				key, strings.Join(kinds, ", "))
		}
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("observation %q has an empty value", entry)
		}
		out = append(out, spotter.Observation{
			Kind: kind, Value: strings.TrimSpace(value), Quality: 1, Sensor: "operator",
		})
	}
	return out, nil
}

func parseExposure(value string) (spotter.Exposure, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "internet":
		return spotter.ExposureInternet, nil
	case "lan":
		return spotter.ExposureLAN, nil
	case "isolated":
		return spotter.ExposureIsolated, nil
	case "unknown", "":
		return spotter.ExposureUnknown, nil
	default:
		return "", fmt.Errorf("unknown exposure %q: use internet, lan, isolated, or unknown", value)
	}
}

// renderSpotTerminal prints the assessment for a person, leading with what to
// do rather than with a list of identifiers.
func renderSpotTerminal(w io.Writer, a spotter.Assessment, enrolled bool) error {
	id := a.Device.Identity

	if !enrolled {
		card := spotter.ToHUD(a, false)
		fmt.Fprintf(w, "\n  %s\n  %s\n\n", card.Line1, card.Line2)
		fmt.Fprintf(w, "  Spotter only assesses devices you have claimed.\n\n")
		return nil
	}

	fmt.Fprintf(w, "\n  IDENTITY\n")
	if id.Named() {
		fmt.Fprintf(w, "    %s %s  [%s]\n", id.Best.Vendor, id.Best.Family, strings.ToUpper(string(id.Band)))
	} else {
		fmt.Fprintf(w, "    Not identified  [%s]\n", strings.ToUpper(string(id.Band)))
	}
	fmt.Fprintf(w, "    %s\n", id.Reason)
	if len(id.Corroborating) > 0 && id.Named() {
		fmt.Fprintf(w, "    evidence: %s\n", strings.Join(id.Corroborating, ", "))
	}
	for _, runner := range id.Runners {
		fmt.Fprintf(w, "    also considered: %s %s (%.1f bits)\n", runner.Vendor, runner.Family, runner.Score)
	}

	fmt.Fprintf(w, "\n  RISK  %s (%.1f/10), exposure %s\n",
		strings.ToUpper(a.RiskBand), a.RiskScore, a.Device.Exposure)
	fmt.Fprintf(w, "    %s\n", a.Headline)

	if len(a.Concerns) > 0 {
		fmt.Fprintf(w, "\n  KNOWN ISSUES\n")
		for _, c := range a.Concerns {
			flag := ""
			if c.KnownExploited {
				flag = "  [ACTIVELY EXPLOITED]"
			}
			fmt.Fprintf(w, "    %-34s %-8s risk %.1f%s\n", c.ID, c.Severity, c.Risk, flag)
			fmt.Fprintf(w, "      %s\n", c.Summary)
			fmt.Fprintf(w, "      confidence: %s — %s\n", c.Confidence, c.Why)
			if c.Source != "" {
				fmt.Fprintf(w, "      %s\n", c.Source)
			}
		}
	}

	if len(a.Plan) > 0 {
		fmt.Fprintf(w, "\n  WHAT TO DO, IN ORDER\n")
		for i, step := range a.Plan {
			fmt.Fprintf(w, "    %d. %s  (%s effort)\n", i+1, step.Do, step.Effort)
		}
	}

	if a.DataNotice != "" {
		fmt.Fprintf(w, "\n  %s\n", a.DataNotice)
	}
	fmt.Fprintln(w)
	return nil
}
