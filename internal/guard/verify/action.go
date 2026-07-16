// Package verify implements the guard's Half B: the consequential-action side
// of intent verification. Layer 2 (static_match) is deterministic, Layer 3
// (judge) is an isolated LLM call, and Layer 4 (drift) is a session-level
// accumulator.
package verify

import (
	"net/url"
	"regexp"
	"strings"
)

// Action is a single consequential action an agent proposes to take.
type Action struct {
	// Type is one of: write, exec, network, push, read.
	Type string `json:"type"`
	// Target is the file path, host/URL, command, or remote the action touches.
	Target string `json:"target"`
	// Network lists hosts this action contacts, when known.
	Network []string `json:"network,omitempty"`
	// Description is optional human context for the action.
	Description string `json:"description,omitempty"`
}

// IsRisky reports whether an action is consequential enough to warrant a
// Layer 3 judge call once it has passed Layer 2.
func (a Action) IsRisky() bool {
	switch a.Type {
	case "write", "exec", "network", "push":
		return true
	case "read":
		return isSensitivePath(a.Target)
	default:
		return false
	}
}

var (
	secretPath = regexp.MustCompile(`(?i)(\.env\b|/\.ssh/|id_rsa\b|id_ed25519\b|credentials\b|/\.aws/|private[_\s-]?key|secret)`)
	hostInText = regexp.MustCompile(`(?i)\bhttps?://([a-z0-9.-]+)`)
	bareHost   = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b`)
	encodeCmd  = regexp.MustCompile(`(?i)\b(base64|xxd|hexdump|openssl\s+enc|gzip|zip|tar\s+.*z|uuencode)\b`)
)

// isSensitivePath reports whether a path points at a secret or credential.
func isSensitivePath(p string) bool {
	return secretPath.MatchString(p)
}

// hostsIn extracts candidate hostnames from an action's Network list and its
// Target (which may be a URL, a bare host, or a shell command containing one).
func hostsIn(a Action) []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}

	for _, h := range a.Network {
		add(h)
	}

	// A URL anywhere in the target.
	for _, m := range hostInText.FindAllStringSubmatch(a.Target, -1) {
		add(m[1])
	}

	// A target that is itself a URL or host:port.
	if u, err := url.Parse(strings.TrimSpace(a.Target)); err == nil && u.Host != "" {
		add(u.Hostname())
	} else if a.Type == "network" || a.Type == "push" {
		// For explicit network/push actions, treat a bare dotted token as a host.
		if m := bareHost.FindStringSubmatch(a.Target); m != nil {
			add(m[1])
		}
	}

	return hosts
}
