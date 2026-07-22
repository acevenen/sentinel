package hunt

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleHAR() []byte {
	return []byte(`{"log":{"entries":[
		{"request":{"method":"GET","url":"https://api.example.com/v1/orders/1001"},"response":{"status":200}},
		{"request":{"method":"GET","url":"https://api.example.com/v1/orders/1002"},"response":{"status":200}},
		{"request":{"method":"GET","url":"https://api.example.com/v1/users/42/profile"},"response":{"status":200}},
		{"request":{"method":"GET","url":"https://api.example.com/v1/accounts/550e8400-e29b-41d4-a716-446655440000"},"response":{"status":200}},
		{"request":{"method":"POST","url":"https://api.example.com/v1/orders"},"response":{"status":201}},
		{"request":{"method":"GET","url":"https://api.example.com/v1/health"},"response":{"status":200}},
		{"request":{"method":"GET","url":"https://cdn.example.com/static/logo.png"},"response":{"status":200}}
	]}}`)
}

func findRequest(p Program, path string) (RequestTemplate, bool) {
	for _, r := range p.Requests {
		if r.Path == path {
			return r, true
		}
	}
	return RequestTemplate{}, false
}

func TestImportHARBasic(t *testing.T) {
	p, err := ImportHAR(sampleHAR(), nil, ImportOptions{Identity: "alice", Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}

	// Read-only object endpoints only: orders (templated + deduped), nested user
	// profile, and the UUID account. The POST, /health, and the CDN asset drop.
	if len(p.Requests) != 3 {
		t.Fatalf("got %d request templates, want 3: %+v", len(p.Requests), p.Requests)
	}

	orders, ok := findRequest(p, "/v1/orders/{id}")
	if !ok {
		t.Fatal("orders endpoint was not templated")
	}
	if len(orders.Owned["alice"]) != 2 {
		t.Errorf("orders should own 2 ids for alice, got %v", orders.Owned["alice"])
	}

	if _, ok := findRequest(p, "/v1/users/{id}/profile"); !ok {
		t.Error("nested id endpoint /v1/users/{id}/profile not templated")
	}
	if _, ok := findRequest(p, "/v1/accounts/{id}"); !ok {
		t.Error("uuid endpoint not templated")
	}

	// Base URL and scope come only from the host that yielded endpoints.
	if p.BaseURL != "https://api.example.com" {
		t.Errorf("base_url = %q", p.BaseURL)
	}
	if len(p.InScope) != 1 || p.InScope[0] != "api.example.com" {
		t.Errorf("in_scope should be only api.example.com (not the CDN host), got %v", p.InScope)
	}

	// Identity is created with a default token env var.
	if !hasIdentity(p, "alice") {
		t.Fatal("alice identity not created")
	}
	if p.Identities[0].TokenEnv != "HUNT_ALICE_TOKEN" {
		t.Errorf("token env = %q", p.Identities[0].TokenEnv)
	}
}

func TestImportHARMergesSecondIdentity(t *testing.T) {
	alice, err := ImportHAR(sampleHAR(), nil, ImportOptions{Identity: "alice"})
	if err != nil {
		t.Fatal(err)
	}

	bobHAR := []byte(`{"log":{"entries":[
		{"request":{"method":"GET","url":"https://api.example.com/v1/orders/2002"},"response":{"status":200}}
	]}}`)
	merged, err := ImportHAR(bobHAR, &alice, ImportOptions{Identity: "bob"})
	if err != nil {
		t.Fatal(err)
	}

	if !hasIdentity(merged, "alice") || !hasIdentity(merged, "bob") {
		t.Fatal("merged program should carry both identities")
	}
	orders, ok := findRequest(merged, "/v1/orders/{id}")
	if !ok {
		t.Fatal("orders endpoint missing after merge")
	}
	if len(orders.Owned["alice"]) != 2 || len(orders.Owned["bob"]) != 1 {
		t.Errorf("orders ownership wrong after merge: %v", orders.Owned)
	}
	// The merged manifest now has two identities owning objects on the same
	// endpoint — exactly what a cross-account test needs.
	if merged.Requests[0].Owned["bob"][0] != "2002" {
		t.Errorf("bob's object not recorded: %v", orders.Owned["bob"])
	}
}

func TestImportHARDedupesOwnedIDs(t *testing.T) {
	dupHAR := []byte(`{"log":{"entries":[
		{"request":{"method":"GET","url":"https://api.example.com/v1/orders/1001"},"response":{"status":200}},
		{"request":{"method":"GET","url":"https://api.example.com/v1/orders/1001"},"response":{"status":200}}
	]}}`)
	p, err := ImportHAR(dupHAR, nil, ImportOptions{Identity: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Requests[0].Owned["alice"]; len(got) != 1 {
		t.Errorf("duplicate object id should be deduped, got %v", got)
	}
}

func TestImportHARNoObjectEndpoints(t *testing.T) {
	noIDs := []byte(`{"log":{"entries":[
		{"request":{"method":"GET","url":"https://api.example.com/v1/health"},"response":{"status":200}},
		{"request":{"method":"GET","url":"https://api.example.com/login"},"response":{"status":200}}
	]}}`)
	if _, err := ImportHAR(noIDs, nil, ImportOptions{Identity: "alice"}); err == nil {
		t.Error("import should error when no object-bearing endpoints are found")
	}
}

func TestImportHARRequiresIdentity(t *testing.T) {
	if _, err := ImportHAR(sampleHAR(), nil, ImportOptions{}); err == nil {
		t.Error("import should require an identity")
	}
}

func TestTemplatePath(t *testing.T) {
	tests := []struct {
		path     string
		wantTmpl string
		wantID   string
		wantOK   bool
	}{
		{"/v1/orders/1001", "/v1/orders/{id}", "1001", true},
		{"/v1/users/42/profile", "/v1/users/{id}/profile", "42", true},
		{"/v1/accounts/550e8400-e29b-41d4-a716-446655440000", "/v1/accounts/{id}", "550e8400-e29b-41d4-a716-446655440000", true},
		{"/v1/health", "", "", false},
		{"/login", "", "", false},
	}
	for _, tt := range tests {
		gotTmpl, gotID, ok := templatePath(tt.path)
		if ok != tt.wantOK || (ok && (gotTmpl != tt.wantTmpl || gotID != tt.wantID)) {
			t.Errorf("templatePath(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.path, gotTmpl, gotID, ok, tt.wantTmpl, tt.wantID, tt.wantOK)
		}
	}
}

func TestRenderProgramYAMLRoundTrips(t *testing.T) {
	p, err := ImportHAR(sampleHAR(), nil, ImportOptions{Identity: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderProgramYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	// The generated YAML must parse back into an equivalent program.
	reparsed, err := ParseProgram(out)
	if err != nil {
		t.Fatalf("generated YAML did not parse: %v", err)
	}
	if len(reparsed.Requests) != len(p.Requests) || reparsed.BaseURL != p.BaseURL {
		t.Errorf("round-trip mismatch: %+v", reparsed)
	}
}

func TestSampleHARFixtureImports(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "hunt", "capture-alice.har")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("sample HAR not present: %v", err)
	}
	if _, err := ImportHAR(data, nil, ImportOptions{Identity: "alice"}); err != nil {
		t.Errorf("sample capture-alice.har failed to import: %v", err)
	}
}
