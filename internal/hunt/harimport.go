package hunt

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ImportOptions configures a HAR import.
type ImportOptions struct {
	// Identity is the test account whose traffic this HAR captures; discovered
	// object IDs are recorded as owned by this identity.
	Identity string
	// BaseURL overrides the inferred base URL (optional).
	BaseURL string
	// Name sets the program name when starting a fresh program (optional).
	Name string
}

// har is the minimal HTTP Archive shape we read. Browsers' DevTools "Save all
// as HAR" and Burp Suite's HAR export both produce this.
type har struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
			Response struct {
				Status int `json:"status"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

var (
	numericID = regexp.MustCompile(`^\d+$`)
	uuidID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexID     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	slugClean = regexp.MustCompile(`[^a-z0-9]+`)
)

// ImportHAR reads a HAR capture and folds its object-bearing read requests into
// a program manifest for the given identity. Pass an existing program as base
// to merge a second account's capture into it; pass nil to start fresh.
//
// It is conservative: only read-only (GET/HEAD) requests whose path contains an
// identifier-looking segment become request templates, so a starting manifest
// is produced without inventing endpoints. The researcher still reviews scope
// and object ownership before running.
func ImportHAR(harData []byte, base *Program, opts ImportOptions) (Program, error) {
	if strings.TrimSpace(opts.Identity) == "" {
		return Program{}, fmt.Errorf("import requires an --identity to own the discovered objects")
	}

	var h har
	if err := json.Unmarshal(harData, &h); err != nil {
		return Program{}, fmt.Errorf("parsing HAR: %w", err)
	}

	p := Program{Platform: "hackerone"}
	if base != nil {
		p = *base
	}
	if p.Name == "" {
		p.Name = firstNonEmpty(opts.Name, "imported-program")
	}

	// Index existing templates so a merge accumulates into them.
	index := map[string]int{}
	for i, r := range p.Requests {
		index[r.Method+" "+r.Path] = i
	}

	// Only hosts that actually yield a testable endpoint are scoped — an asset
	// or CDN host that appears in the capture but has no object endpoint is not
	// auto-authorized.
	hostScheme := map[string]string{}
	hostCount := map[string]int{}

	for _, e := range h.Log.Entries {
		method := strings.ToUpper(strings.TrimSpace(e.Request.Method))
		if !readOnlyMethod(method) {
			continue // read-only only, matching hunt's own guardrail
		}
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Host == "" {
			continue
		}

		tmplPath, objectID, ok := templatePath(u.Path)
		if !ok {
			continue // no identifier-looking segment — not an object endpoint
		}

		host := strings.ToLower(u.Hostname())
		hostCount[host]++
		if _, ok := hostScheme[host]; !ok {
			hostScheme[host] = u.Scheme
		}

		key := method + " " + tmplPath
		if i, exists := index[key]; exists {
			addOwned(&p.Requests[i], opts.Identity, objectID)
		} else {
			rt := RequestTemplate{
				ID:     uniqueRequestID(p.Requests, requestSlug(tmplPath)),
				Method: method,
				Path:   tmplPath,
				Owned:  map[string][]string{},
			}
			addOwned(&rt, opts.Identity, objectID)
			p.Requests = append(p.Requests, rt)
			index[key] = len(p.Requests) - 1
		}
	}

	if len(p.Requests) == 0 {
		return Program{}, fmt.Errorf("no read-only object-bearing requests found in the HAR (nothing with a numeric/UUID/hex id in the path)")
	}

	// Base URL and scope, derived from the busiest host unless overridden.
	top := busiestHost(hostCount)
	if p.BaseURL == "" {
		if opts.BaseURL != "" {
			p.BaseURL = opts.BaseURL
		} else if top != "" {
			scheme := firstNonEmpty(hostScheme[top], "https")
			p.BaseURL = scheme + "://" + top
		}
	}
	p.InScope = mergeHosts(p.InScope, hostCount)

	// Ensure the identity exists with a sensible default token env var.
	if !hasIdentity(p, opts.Identity) {
		p.Identities = append(p.Identities, Identity{
			Name:     opts.Identity,
			Header:   "Authorization",
			Prefix:   "Bearer ",
			TokenEnv: "HUNT_" + strings.ToUpper(sanitizeEnv(opts.Identity)) + "_TOKEN",
		})
	}

	return p, nil
}

// templatePath replaces the last identifier-looking path segment with {id} and
// returns the template, the extracted object ID, and whether one was found.
// Only the last such segment is templated so account-specific prefixes (e.g.
// /users/42/orders/1001 → /users/42/orders/{id}) stay concrete.
func templatePath(path string) (string, string, bool) {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if isIDLike(segs[i]) {
			id := segs[i]
			segs[i] = idPlaceholder
			return strings.Join(segs, "/"), id, true
		}
	}
	return path, "", false
}

// isIDLike reports whether a path segment looks like an object identifier.
func isIDLike(seg string) bool {
	return numericID.MatchString(seg) || uuidID.MatchString(seg) || hexID.MatchString(seg)
}

// addOwned records that identity owns objectID under a request template,
// de-duplicating.
func addOwned(r *RequestTemplate, identity, objectID string) {
	if r.Owned == nil {
		r.Owned = map[string][]string{}
	}
	for _, existing := range r.Owned[identity] {
		if existing == objectID {
			return
		}
	}
	r.Owned[identity] = append(r.Owned[identity], objectID)
	sort.Strings(r.Owned[identity])
}

// requestSlug derives a readable request id from a templated path.
func requestSlug(tmplPath string) string {
	cleaned := strings.ReplaceAll(tmplPath, idPlaceholder, "")
	slug := strings.Trim(slugClean.ReplaceAllString(strings.ToLower(cleaned), "-"), "-")
	if slug == "" {
		return "endpoint"
	}
	return slug
}

// uniqueRequestID appends a numeric suffix if base collides with an existing id.
func uniqueRequestID(existing []RequestTemplate, base string) string {
	taken := map[string]bool{}
	for _, r := range existing {
		taken[r.ID] = true
	}
	if !taken[base] {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if !taken[candidate] {
			return candidate
		}
	}
}

func hasIdentity(p Program, name string) bool {
	for _, id := range p.Identities {
		if id.Name == name {
			return true
		}
	}
	return false
}

// mergeHosts adds discovered hostnames to an existing in-scope list, sorted and
// de-duplicated.
func mergeHosts(existing []string, discovered map[string]int) []string {
	set := map[string]bool{}
	for _, h := range existing {
		set[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for h := range discovered {
		set[h] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		if h != "" {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func busiestHost(counts map[string]int) string {
	var top string
	best := -1
	for h, c := range counts {
		if c > best || (c == best && h < top) {
			top, best = h, c
		}
	}
	return top
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func sanitizeEnv(s string) string {
	return strings.Trim(slugClean.ReplaceAllString(strings.ToLower(s), "_"), "_")
}

// programHeader annotates a generated manifest with the next steps a researcher
// must take before it is safe and complete to run.
const programHeader = `# Generated by ` + "`sentinel hunt import`" + ` from a HAR capture.
#
# Before running, review and complete:
#   1. Scope — confirm in_scope/out_of_scope match the program's authorized scope.
#   2. Ownership — object IDs are grouped by the --identity of each capture. Import
#      a second account's HAR (merge with --program) so every endpoint has at least
#      two identities, each owning its own objects.
#   3. Tokens — export each identity's token_env before running (never stored here).
#   4. Severity — mark sensitive-data endpoints (payments, PII) as ` + "`severity: critical`" + `.
#
# Only run against programs that authorize testing.
`

// RenderProgramYAML marshals a program to annotated YAML suitable for writing to
// a program manifest file.
func RenderProgramYAML(p Program) ([]byte, error) {
	body, err := yaml.Marshal(p)
	if err != nil {
		return nil, err
	}
	return append([]byte(programHeader+"\n"), body...), nil
}
