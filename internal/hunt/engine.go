package hunt

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Engine runs the IDOR/BOLA differential test: for each request template, it
// establishes a per-identity baseline (each identity fetching its own objects),
// then replays one identity's objects using another identity's session. If the
// attacker receives the victim's object, object-level authorization is broken.
type Engine struct {
	program Program
	gate    *ScopeGate
	client  *Client
	tokens  map[string]string // identity name -> session token (from env)
}

// NewEngine builds an engine. tokens holds each identity's session token, read
// from the environment by the caller so secrets never live in the manifest.
func NewEngine(p Program, doer Doer, tokens map[string]string) *Engine {
	gate := NewScopeGate(p)
	return &Engine{
		program: p,
		gate:    gate,
		client:  NewClient(doer, gate, p.RateLimitRPS),
		tokens:  tokens,
	}
}

// identity looks up a declared identity by name.
func (e *Engine) identity(name string) (Identity, bool) {
	for _, id := range e.program.Identities {
		if id.Name == name {
			return id, true
		}
	}
	return Identity{}, false
}

// resolveURL builds the concrete URL for a template and object ID. A template
// path may be absolute (used as-is) or relative (joined to base_url).
func (e *Engine) resolveURL(tmpl RequestTemplate, objectID string) (string, error) {
	path := strings.ReplaceAll(tmpl.Path, idPlaceholder, url.PathEscape(objectID))
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	base, err := url.Parse(e.program.BaseURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

// Plan returns every request the engine would issue and its scope decision,
// without sending anything. It powers --dry-run so a researcher can confirm
// scope before touching a target.
func (e *Engine) Plan() []PlanStep {
	var steps []PlanStep
	add := func(reqID, method, rawURL, identity, kind string) {
		inScope := false
		if u, err := url.Parse(rawURL); err == nil {
			inScope = e.gate.InScope(u.Hostname())
		}
		steps = append(steps, PlanStep{RequestID: reqID, Method: method, URL: rawURL, Identity: identity, Kind: kind, InScope: inScope})
	}

	for _, tmpl := range e.program.Requests {
		method := methodOf(tmpl)
		// Baselines: each identity fetches its own objects.
		for name, ids := range tmpl.Owned {
			for _, oid := range ids {
				if raw, err := e.resolveURL(tmpl, oid); err == nil {
					add(tmpl.ID, method, raw, name, "baseline")
				}
			}
		}
		// Cross-account: attacker fetches victim's objects.
		for _, attacker := range e.program.Identities {
			for victimName, ids := range tmpl.Owned {
				if victimName == attacker.Name {
					continue
				}
				for _, oid := range ids {
					if raw, err := e.resolveURL(tmpl, oid); err == nil {
						add(tmpl.ID, method, raw, attacker.Name, "cross-account")
					}
				}
			}
		}
	}
	return steps
}

// Run executes the full differential test and returns a report. It requires a
// token for every identity referenced by a template; a missing token is a hard
// error, not a silent skip.
func (e *Engine) Run(ctx context.Context) (Report, error) {
	rep := Report{Program: e.program.Name}

	for _, tmpl := range e.program.Requests {
		method := methodOf(tmpl)

		// 1. Baselines: each identity fetches its own objects. These confirm the
		// endpoint works and record what a legitimate owner's response looks like.
		type baseline struct {
			status int
			sig    string
		}
		baselines := map[string]map[string]baseline{} // identity -> objectID -> baseline

		for name, ids := range tmpl.Owned {
			id, ok := e.identity(name)
			if !ok {
				continue
			}
			token, ok := e.tokens[name]
			if !ok || token == "" {
				return Report{}, fmt.Errorf("no session token for identity %q (set %s)", name, id.TokenEnv)
			}
			baselines[name] = map[string]baseline{}
			for _, oid := range ids {
				resp, skipped, err := e.send(ctx, tmpl, oid, id, token, &rep)
				if err != nil {
					rep.Errors = append(rep.Errors, fmt.Sprintf("baseline %s/%s as %s: %v", tmpl.ID, oid, name, err))
					continue
				}
				if skipped {
					continue
				}
				rep.BaselinesRun++
				baselines[name][oid] = baseline{status: resp.Status, sig: bodySig(resp.Body)}
			}
		}

		// 2. Cross-account tests: each attacker fetches each victim's objects.
		for _, attacker := range e.program.Identities {
			token, ok := e.tokens[attacker.Name]
			if !ok || token == "" {
				continue // baseline step already errored on any required token
			}
			for victimName, ids := range tmpl.Owned {
				if victimName == attacker.Name {
					continue
				}
				for _, oid := range ids {
					base, hasBase := baselines[victimName][oid]
					resp, skipped, err := e.send(ctx, tmpl, oid, attacker, token, &rep)
					if err != nil {
						rep.Errors = append(rep.Errors, fmt.Sprintf("cross %s/%s as %s: %v", tmpl.ID, oid, attacker.Name, err))
						continue
					}
					if skipped {
						continue
					}
					rep.TestsRun++

					// Confirmed BOLA: the attacker got the victim's exact object
					// (success status AND body identical to the victim's own
					// baseline). Requiring the body match rules out generic 200s.
					if hasBase && resp.Status == tmpl.Status() && resp.Status == base.status && bodySig(resp.Body) == base.sig {
						raw, _ := e.resolveURL(tmpl, oid)
						rep.Findings = append(rep.Findings, Finding{
							RequestID: tmpl.ID,
							Endpoint:  raw,
							Method:    method,
							Attacker:  attacker.Name,
							Victim:    victimName,
							ObjectID:  oid,
							Status:    resp.Status,
							Severity:  tmpl.FindingSeverity(),
							Evidence: fmt.Sprintf(
								"%s's session returned %s's object %q (HTTP %d, response body byte-identical to %s's own baseline)",
								attacker.Name, victimName, oid, resp.Status, victimName),
						})
					}
				}
			}
		}
	}

	return rep, nil
}

// send issues one request, folding out-of-scope refusals into the report rather
// than treating them as fatal.
func (e *Engine) send(ctx context.Context, tmpl RequestTemplate, objectID string, id Identity, token string, rep *Report) (Response, bool, error) {
	raw, err := e.resolveURL(tmpl, objectID)
	if err != nil {
		return Response{}, false, err
	}
	value := id.Prefix + token
	resp, err := e.client.Get(ctx, methodOf(tmpl), raw, id.Header, value)
	if err != nil {
		if errors.Is(err, ErrOutOfScope) {
			rep.OutOfScopeSkipped++
			return Response{}, true, nil
		}
		return Response{}, false, err
	}
	return resp, false, nil
}

func methodOf(tmpl RequestTemplate) string {
	if strings.TrimSpace(tmpl.Method) == "" {
		return "GET"
	}
	return strings.ToUpper(tmpl.Method)
}

// bodySig is a stable signature of a response body for equality comparison.
func bodySig(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum)
}
