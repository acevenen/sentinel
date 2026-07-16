package verify

import (
	"fmt"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/acevenen/sentinel/internal/guard/intent"
)

// MatchResult is the outcome of Layer 2 static matching.
type MatchResult struct {
	OK     bool
	Reason string
}

// StaticMatch is Layer 2: a deterministic comparison of a proposed action
// against the declared intent. It is pure Go with no LLM and is intended to be
// airtight on its two core rules — a network action may only reach hosts in
// AllowedNetwork, and a write may only land inside Scope.
func StaticMatch(in intent.Intent, a Action) MatchResult {
	switch a.Type {
	case "network", "push":
		return matchNetwork(in, a)
	case "write":
		return matchWrite(in, a)
	case "exec":
		return matchExec(in, a)
	default:
		// read and unknown types have no deterministic intent contract here;
		// they flow to the drift accumulator instead.
		return MatchResult{OK: true}
	}
}

func matchNetwork(in intent.Intent, a Action) MatchResult {
	hosts := hostsIn(a)
	if len(hosts) == 0 {
		return MatchResult{OK: false, Reason: fmt.Sprintf("%s action declares no host to check against AllowedNetwork", a.Type)}
	}
	for _, h := range hosts {
		if !in.AllowsHost(h) {
			return MatchResult{OK: false, Reason: fmt.Sprintf("host %q is not in the declared AllowedNetwork %v", h, in.AllowedNetwork)}
		}
	}
	return MatchResult{OK: true}
}

func matchWrite(in intent.Intent, a Action) MatchResult {
	target := normalizePath(a.Target)
	if target == "" {
		return MatchResult{OK: false, Reason: "write action declares no target path"}
	}
	if len(in.Scope) == 0 {
		return MatchResult{OK: false, Reason: fmt.Sprintf("write to %q but the declared intent grants no write Scope", a.Target)}
	}
	for _, glob := range in.Scope {
		if pathInScope(target, glob) {
			return MatchResult{OK: true}
		}
	}
	return MatchResult{OK: false, Reason: fmt.Sprintf("write target %q is outside the declared Scope %v", a.Target, in.Scope)}
}

// matchExec is best-effort: it blocks a command that reaches a host outside
// AllowedNetwork or references a secret path. The two airtight rules above
// carry the guarantees; exec is a defensive extra.
func matchExec(in intent.Intent, a Action) MatchResult {
	if isSensitivePath(a.Target) {
		return MatchResult{OK: false, Reason: fmt.Sprintf("exec command references a secret path: %q", a.Target)}
	}
	for _, h := range hostsIn(a) {
		if !in.AllowsHost(h) {
			return MatchResult{OK: false, Reason: fmt.Sprintf("exec command contacts host %q outside AllowedNetwork %v", h, in.AllowedNetwork)}
		}
	}
	return MatchResult{OK: true}
}

// normalizePath converts a target to a clean, slash-separated relative path for
// glob matching.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	return strings.TrimPrefix(p, "./")
}

// pathInScope reports whether target matches a scope glob, treating a bare
// directory prefix (e.g. "internal/") as "everything under it".
func pathInScope(target, glob string) bool {
	glob = strings.ReplaceAll(strings.TrimSpace(glob), "\\", "/")
	glob = strings.TrimPrefix(glob, "./")
	if glob == "" {
		return false
	}
	if ok, err := doublestar.Match(glob, target); err == nil && ok {
		return true
	}
	// Directory prefix: "internal/" or "internal" allows "internal/foo/bar".
	prefix := strings.TrimSuffix(glob, "/")
	if target == prefix || strings.HasPrefix(target, prefix+"/") {
		return true
	}
	// A glob ending in "/**" should also match the directory itself.
	if strings.HasSuffix(glob, "/**") {
		base := strings.TrimSuffix(glob, "/**")
		if target == base || strings.HasPrefix(target, base+"/") {
			return true
		}
	}
	return false
}
