package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func post(t *testing.T, s *Server, path, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	if token != "" {
		req.Header.Set("X-Sentinel-Token", token)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestIndexServedWithToken(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index status = %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "__SENTINEL_TOKEN__") {
		t.Error("token placeholder was not substituted")
	}
	if !strings.Contains(body, s.Token()) {
		t.Error("served page does not carry the launch token")
	}
}

func TestAPIRequiresToken(t *testing.T) {
	s := newTestServer(t)
	if rr := post(t, s, "/api/samples", "", map[string]string{}); rr.Code != http.StatusForbidden {
		t.Errorf("no-token request = %d, want 403", rr.Code)
	}
	if rr := post(t, s, "/api/samples", "wrong", map[string]string{}); rr.Code != http.StatusForbidden {
		t.Errorf("bad-token request = %d, want 403", rr.Code)
	}
	if rr := post(t, s, "/api/samples", s.Token(), map[string]string{"which": "hunt-program"}); rr.Code != http.StatusOK {
		t.Errorf("valid-token request = %d, want 200", rr.Code)
	}
}

func TestAPIRejectsGet(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/samples", nil)
	req.Header.Set("X-Sentinel-Token", s.Token())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on API = %d, want 405", rr.Code)
	}
}

func TestEvaluateEndpoint(t *testing.T) {
	s := newTestServer(t)
	agent := post(t, s, "/api/samples", s.Token(), map[string]string{"which": "evaluate-agent"})
	var sm struct {
		Content string `json:"content"`
	}
	_ = json.Unmarshal(agent.Body.Bytes(), &sm)

	rr := post(t, s, "/api/evaluate", s.Token(), map[string]string{"agent": sm.Content})
	if rr.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d", rr.Code)
	}
	var resp struct {
		Report struct {
			Score          int    `json:"Score"`
			Recommendation string `json:"Recommendation"`
		} `json:"report"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("evaluate response not JSON: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("evaluate returned error: %s", resp.Error)
	}
	if resp.Report.Score != 100 || resp.Report.Recommendation == "" {
		t.Errorf("unexpected evaluate report: %+v", resp.Report)
	}
}

func TestHuntPlanEndpoint(t *testing.T) {
	s := newTestServer(t)
	prog := post(t, s, "/api/samples", s.Token(), map[string]string{"which": "hunt-program"})
	var sm struct {
		Content string `json:"content"`
	}
	_ = json.Unmarshal(prog.Body.Bytes(), &sm)

	rr := post(t, s, "/api/hunt/plan", s.Token(), map[string]string{"program": sm.Content})
	var resp struct {
		Steps []map[string]interface{} `json:"steps"`
		Error string                   `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error != "" {
		t.Fatalf("plan error: %s", resp.Error)
	}
	if len(resp.Steps) == 0 {
		t.Error("plan returned no steps")
	}
}

func TestHuntImportEndpoint(t *testing.T) {
	s := newTestServer(t)
	har := post(t, s, "/api/samples", s.Token(), map[string]string{"which": "hunt-har"})
	var sm struct {
		Content string `json:"content"`
	}
	_ = json.Unmarshal(har.Body.Bytes(), &sm)

	rr := post(t, s, "/api/hunt/import", s.Token(), map[string]string{"har": sm.Content, "identity": "alice"})
	var resp struct {
		ProgramYAML string `json:"program_yaml"`
		Endpoints   int    `json:"endpoints"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error != "" {
		t.Fatalf("import error: %s", resp.Error)
	}
	if resp.Endpoints == 0 || !strings.Contains(resp.ProgramYAML, "{id}") {
		t.Errorf("unexpected import result: endpoints=%d", resp.Endpoints)
	}
}

func TestGuardEndpoint(t *testing.T) {
	s := newTestServer(t)
	in := post(t, s, "/api/samples", s.Token(), map[string]string{"which": "guard-intent"})
	st := post(t, s, "/api/samples", s.Token(), map[string]string{"which": "guard-stream"})
	var im, sm struct {
		Content string `json:"content"`
	}
	_ = json.Unmarshal(in.Body.Bytes(), &im)
	_ = json.Unmarshal(st.Body.Bytes(), &sm)

	rr := post(t, s, "/api/guard", s.Token(), map[string]string{"intent": im.Content, "stream": sm.Content})
	var resp struct {
		Session struct {
			Blocked bool `json:"Blocked"`
		} `json:"session"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error != "" {
		t.Fatalf("guard error: %s", resp.Error)
	}
	if !resp.Session.Blocked {
		t.Error("guard sample stream should be blocked")
	}
}

func TestEvaluateBadInput(t *testing.T) {
	s := newTestServer(t)
	rr := post(t, s, "/api/evaluate", s.Token(), map[string]string{"agent": "not: [valid"})
	var resp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error == "" {
		t.Error("invalid agent manifest should return an error message")
	}
}
