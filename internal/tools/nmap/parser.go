package nmap

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/acevenen/sentinel/internal/tools"
)

type nmapRun struct {
	Hosts []host `xml:"host"`
}

type host struct {
	Status    status     `xml:"status"`
	Addresses []address  `xml:"address"`
	Hostnames []hostname `xml:"hostnames>hostname"`
	Ports     []port     `xml:"ports>port"`
}

type status struct {
	State string `xml:"state,attr"`
}

type address struct {
	Value string `xml:"addr,attr"`
	Type  string `xml:"addrtype,attr"`
}

type hostname struct {
	Name string `xml:"name,attr"`
}

type port struct {
	Protocol string   `xml:"protocol,attr"`
	ID       int      `xml:"portid,attr"`
	State    state    `xml:"state"`
	Service  service  `xml:"service"`
	Scripts  []script `xml:"script"`
}

type state struct {
	Value  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

type script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ParseXML converts canned or live nmap XML to the normalized finding model.
func ParseXML(data []byte) ([]tools.Finding, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}
	var findings []tools.Finding
	for _, scannedHost := range run.Hosts {
		if scannedHost.Status.State != "" && scannedHost.Status.State != "up" {
			continue
		}
		target := hostAddress(scannedHost)
		hostName := ""
		if len(scannedHost.Hostnames) > 0 {
			hostName = scannedHost.Hostnames[0].Name
		}
		for _, scannedPort := range scannedHost.Ports {
			if scannedPort.State.Value != "open" && scannedPort.State.Value != "open|filtered" {
				continue
			}
			protocol := strings.ToLower(scannedPort.Protocol)
			serviceName := scannedPort.Service.Name
			title := fmt.Sprintf("Open %s port %d", strings.ToUpper(protocol), scannedPort.ID)
			if serviceName != "" {
				title += " (" + serviceName + ")"
			}
			metadata := map[string]string{
				"port":     fmt.Sprintf("%d", scannedPort.ID),
				"protocol": protocol,
				"state":    scannedPort.State.Value,
			}
			addMetadata(metadata, "hostname", hostName)
			addMetadata(metadata, "service", serviceName)
			addMetadata(metadata, "product", scannedPort.Service.Product)
			addMetadata(metadata, "version", scannedPort.Service.Version)
			addMetadata(metadata, "extra_info", scannedPort.Service.ExtraInfo)
			findings = append(findings, tools.Finding{
				ID:          fmt.Sprintf("nmap:%s:%s:%d", target, protocol, scannedPort.ID),
				Title:       title,
				Description: serviceDescription(scannedPort.Service),
				Severity:    "info",
				Target:      target,
				Evidence:    "state=" + scannedPort.State.Value + " reason=" + scannedPort.State.Reason,
				Metadata:    metadata,
			})
			for _, scannedScript := range scannedPort.Scripts {
				findings = append(findings, tools.Finding{
					ID:       fmt.Sprintf("nmap:%s:%s:%d:script:%s", target, protocol, scannedPort.ID, scannedScript.ID),
					Title:    fmt.Sprintf("Nmap script %s on %s:%d", scannedScript.ID, target, scannedPort.ID),
					Severity: "info",
					Target:   target,
					Evidence: scannedScript.Output,
					Metadata: map[string]string{
						"port":      fmt.Sprintf("%d", scannedPort.ID),
						"protocol":  protocol,
						"script_id": scannedScript.ID,
					},
				})
			}
		}
	}
	return findings, nil
}

func hostAddress(scannedHost host) string {
	for _, address := range scannedHost.Addresses {
		if address.Type == "ipv4" || address.Type == "ipv6" {
			return address.Value
		}
	}
	if len(scannedHost.Addresses) > 0 {
		return scannedHost.Addresses[0].Value
	}
	if len(scannedHost.Hostnames) > 0 {
		return scannedHost.Hostnames[0].Name
	}
	return "unknown"
}

func serviceDescription(value service) string {
	parts := []string{value.Product, value.Version, value.ExtraInfo}
	var cleaned []string
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, " ")
}

func addMetadata(metadata map[string]string, key, value string) {
	if value != "" {
		metadata[key] = value
	}
}
