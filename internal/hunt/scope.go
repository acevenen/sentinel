package hunt

import "strings"

// ScopeGate is the deterministic authorization boundary for every request. It
// is fail-closed: a host is in scope only if it matches an in-scope entry and
// matches no out-of-scope entry. Out-of-scope always wins, and an unrecognized
// host is denied. This is the single most important safety property of hunt —
// it is what keeps testing inside the bug bounty program's authorized scope.
type ScopeGate struct {
	in  []string
	out []string
}

// NewScopeGate builds a gate from a program's in/out scope lists.
func NewScopeGate(p Program) *ScopeGate {
	return &ScopeGate{in: p.InScope, out: p.OutOfScope}
}

// InScope reports whether a host may be contacted. Out-of-scope entries are
// checked first and always win; then in-scope entries; otherwise deny.
func (g *ScopeGate) InScope(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, o := range g.out {
		if hostMatches(o, host) {
			return false
		}
	}
	for _, i := range g.in {
		if hostMatches(i, host) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases and strips a port from a host.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i != -1 {
		// Keep IPv6-in-brackets intact; only strip a trailing :port.
		if !strings.Contains(host[i:], "]") {
			host = host[:i]
		}
	}
	return host
}

// hostMatches reports whether host matches a scope pattern. A bare pattern
// matches that exact host; a "*.domain" pattern matches the domain and any
// subdomain of it.
func hostMatches(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}
