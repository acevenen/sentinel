package hunt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// enginePairProgram returns a two-identity, one-endpoint program pointed at
// baseURL, with alice owning "1001" and bob owning "2002".
func enginePairProgram(baseURL, host string) Program {
	return Program{
		Name:         "test",
		BaseURL:      baseURL,
		InScope:      []string{host},
		RateLimitRPS: 1000, // fast for tests; pacing is verified separately
		Identities: []Identity{
			{Name: "alice", Header: "Authorization", TokenEnv: "A"},
			{Name: "bob", Header: "Authorization", TokenEnv: "B"},
		},
		Requests: []RequestTemplate{
			{ID: "get-order", Method: "GET", Path: "/orders/{id}", Owned: map[string][]string{
				"alice": {"1001"},
				"bob":   {"2002"},
			}},
		},
	}
}

var pairTokens = map[string]string{"alice": "alice-token", "bob": "bob-token"}

// ---- End-to-end against a local httptest server (touches nothing external) ----

// vulnerableOrdersServer returns any order by ID regardless of who asks — the
// BOLA bug.
func vulnerableOrdersServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		fmt.Fprintf(w, `{"order":%q,"secret":"data-for-%s"}`, id, id)
	}))
}

// patchedOrdersServer enforces object-level authorization: each token may only
// read its own order.
func patchedOrdersServer() *httptest.Server {
	owner := map[string]string{"1001": "alice-token", "2002": "bob-token"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		if owner[id] != r.Header.Get("Authorization") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"order":%q,"secret":"data-for-%s"}`, id, id)
	}))
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	// httptest servers listen on 127.0.0.1:port; scope on the bare host.
	u := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(u, ":"); i != -1 {
		return u[:i]
	}
	return u
}

func TestEngineDetectsVulnerableAPI(t *testing.T) {
	srv := vulnerableOrdersServer()
	defer srv.Close()

	prog := enginePairProgram(srv.URL, hostOf(t, srv))
	rep, err := NewEngine(prog, srv.Client(), pairTokens).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 BOLA findings (alice→bob, bob→alice), got %d: %+v", len(rep.Findings), rep.Findings)
	}
	f := rep.Findings[0]
	if f.Severity != SeverityHigh || f.Attacker == f.Victim {
		t.Errorf("unexpected finding shape: %+v", f)
	}
	if rep.TestsRun != 2 || rep.BaselinesRun != 2 {
		t.Errorf("expected 2 baselines + 2 cross-account tests, got %d/%d", rep.BaselinesRun, rep.TestsRun)
	}
}

func TestEngineClearsPatchedAPI(t *testing.T) {
	srv := patchedOrdersServer()
	defer srv.Close()

	prog := enginePairProgram(srv.URL, hostOf(t, srv))
	rep, err := NewEngine(prog, srv.Client(), pairTokens).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("patched API should yield no findings, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.TestsRun != 2 {
		t.Errorf("expected 2 cross-account tests, got %d", rep.TestsRun)
	}
}

// ---- False-positive guard with a mock transport ----

// genericOKDoer returns 200 with the SAME body for every request, as if the API
// returns the caller's own resource. The cross-account body won't match the
// victim's distinct baseline, so this must NOT be flagged.
type genericOKDoer struct{}

func (genericOKDoer) Do(req *http.Request) (*http.Response, error) {
	// Return a body keyed to the AUTH token, not the object — i.e. the API
	// correctly scopes to the caller, just always 200.
	body := fmt.Sprintf(`{"caller":%q}`, req.Header.Get("Authorization"))
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}, nil
}

func TestEngineNoFalsePositiveOnGeneric200(t *testing.T) {
	prog := enginePairProgram("https://api.example.com", "api.example.com")
	rep, err := NewEngine(prog, genericOKDoer{}, pairTokens).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("a generic 200 with per-caller body must not be flagged as BOLA, got %+v", rep.Findings)
	}
}

func TestEngineRequiresTokens(t *testing.T) {
	prog := enginePairProgram("https://api.example.com", "api.example.com")
	_, err := NewEngine(prog, genericOKDoer{}, map[string]string{"alice": "x"}).Run(context.Background())
	if err == nil {
		t.Error("Run should fail when a required identity token is missing")
	}
}

func TestEnginePlanNoRequestsSent(t *testing.T) {
	var sent int
	doer := doerFn(func(*http.Request) (*http.Response, error) { sent++; return nil, nil })
	prog := enginePairProgram("https://api.example.com", "api.example.com")
	steps := NewEngine(prog, doer, pairTokens).Plan()

	if sent != 0 {
		t.Errorf("Plan must not send any requests, sent=%d", sent)
	}
	if len(steps) != 4 { // 2 baselines + 2 cross-account
		t.Errorf("expected 4 planned steps, got %d", len(steps))
	}
	for _, s := range steps {
		if !s.InScope {
			t.Errorf("planned step should be in scope: %+v", s)
		}
	}
}

func TestEnginePlanFlagsOutOfScope(t *testing.T) {
	prog := enginePairProgram("https://api.example.com", "api.example.com")
	// An absolute out-of-scope URL in the path must be flagged (and later refused).
	prog.Requests = append(prog.Requests, RequestTemplate{
		ID: "leak", Method: "GET", Path: "https://evil.example/x/{id}",
		Owned: map[string][]string{"alice": {"9"}},
	})
	steps := NewEngine(prog, doerFn(func(*http.Request) (*http.Response, error) { return nil, nil }), pairTokens).Plan()

	var sawOut bool
	for _, s := range steps {
		if s.RequestID == "leak" && !s.InScope {
			sawOut = true
		}
	}
	if !sawOut {
		t.Error("out-of-scope absolute URL should be flagged as not in scope in the plan")
	}
}

func TestEngineRefusesOutOfScopeAtRuntime(t *testing.T) {
	prog := enginePairProgram("https://api.example.com", "api.example.com")
	prog.Requests = []RequestTemplate{{
		ID: "leak", Method: "GET", Path: "https://evil.example/x/{id}",
		Owned: map[string][]string{"alice": {"9"}, "bob": {"10"}},
	}}
	var sent int
	doer := doerFn(func(*http.Request) (*http.Response, error) { sent++; return nil, nil })
	rep, err := NewEngine(prog, doer, pairTokens).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sent != 0 {
		t.Errorf("out-of-scope requests must never be sent, sent=%d", sent)
	}
	if rep.OutOfScopeSkipped == 0 {
		t.Error("out-of-scope requests should be counted as refused")
	}
	if len(rep.Findings) != 0 {
		t.Error("no findings possible when everything is out of scope")
	}
}

type doerFn func(*http.Request) (*http.Response, error)

func (f doerFn) Do(req *http.Request) (*http.Response, error) { return f(req) }
