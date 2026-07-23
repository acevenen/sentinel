package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/evaluate"
	"github.com/acevenen/sentinel/internal/guard"
	"github.com/acevenen/sentinel/internal/guard/intent"
	"github.com/acevenen/sentinel/internal/guard/verify"
	"github.com/acevenen/sentinel/internal/hunt"
	"github.com/acevenen/sentinel/internal/report"
)

// writeJSON encodes v as a 200 JSON response. All API results — including
// domain errors — return 200 with a body the frontend renders; only transport
// and auth failures use non-200 statuses (handled in the middleware).
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// fail writes an {error} JSON body so the frontend can render the message
// inline rather than treating it as a transport failure.
func fail(w http.ResponseWriter, msg string) {
	writeJSON(w, map[string]string{"error": msg})
}

func decode(r *http.Request, v interface{}) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Hunt: HAR import -------------------------------------------------------

func (s *Server) handleHuntImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HAR      string `json:"har"`
		Identity string `json:"identity"`
		BaseURL  string `json:"base_url"`
		Name     string `json:"name"`
		Program  string `json:"program"` // optional existing manifest to merge into
	}
	if err := decode(r, &req); err != nil {
		fail(w, "bad request: "+err.Error())
		return
	}

	var base *hunt.Program
	if strings.TrimSpace(req.Program) != "" {
		p, err := hunt.ParseProgram([]byte(req.Program))
		if err != nil {
			fail(w, "existing manifest did not parse: "+err.Error())
			return
		}
		base = &p
	}

	program, err := hunt.ImportHAR([]byte(req.HAR), base, hunt.ImportOptions{
		Identity: req.Identity, BaseURL: req.BaseURL, Name: req.Name,
	})
	if err != nil {
		fail(w, err.Error())
		return
	}
	out, err := hunt.RenderProgramYAML(program)
	if err != nil {
		fail(w, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"program_yaml": string(out),
		"endpoints":    len(program.Requests),
	})
}

// --- Hunt: dry-run plan -----------------------------------------------------

func (s *Server) handleHuntPlan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Program string `json:"program"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, "bad request: "+err.Error())
		return
	}
	program, err := hunt.ParseProgram([]byte(req.Program))
	if err != nil {
		fail(w, err.Error())
		return
	}
	if err := program.Validate(); err != nil {
		fail(w, err.Error())
		return
	}
	engine := hunt.NewEngine(program, hunt.DefaultTransport(), nil)
	writeJSON(w, map[string]interface{}{"steps": engine.Plan()})
}

// --- Hunt: run --------------------------------------------------------------

func (s *Server) handleHuntRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Program string            `json:"program"`
		Tokens  map[string]string `json:"tokens"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, "bad request: "+err.Error())
		return
	}
	program, err := hunt.ParseProgram([]byte(req.Program))
	if err != nil {
		fail(w, err.Error())
		return
	}
	if err := program.Validate(); err != nil {
		fail(w, err.Error())
		return
	}
	var missing []string
	for _, id := range program.Identities {
		if strings.TrimSpace(req.Tokens[id.Name]) == "" {
			missing = append(missing, id.Name)
		}
	}
	if len(missing) > 0 {
		fail(w, "missing session token(s) for: "+strings.Join(missing, ", "))
		return
	}

	engine := hunt.NewEngine(program, hunt.DefaultTransport(), req.Tokens)
	rep, err := engine.Run(r.Context())
	if err != nil {
		fail(w, err.Error())
		return
	}
	var md bytes.Buffer
	_ = report.RenderHunt(&md, report.HuntFormatMarkdown, rep)
	writeJSON(w, map[string]interface{}{
		"report":   rep,
		"markdown": md.String(),
	})
}

// --- Evaluate ---------------------------------------------------------------

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Agent string `json:"agent"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, "bad request: "+err.Error())
		return
	}
	var m evaluate.AgentManifest
	if err := yaml.Unmarshal([]byte(req.Agent), &m); err != nil {
		fail(w, "agent manifest did not parse: "+err.Error())
		return
	}
	if err := m.Validate(); err != nil {
		fail(w, err.Error())
		return
	}
	scenarios, err := evaluate.DefaultScenarios()
	if err != nil {
		fail(w, err.Error())
		return
	}
	rep := evaluate.Evaluate(r.Context(), m, scenarios, s.judge())
	writeJSON(w, map[string]interface{}{"report": rep})
}

// --- Guard ------------------------------------------------------------------

func (s *Server) handleGuard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Intent string `json:"intent"`
		Stream string `json:"stream"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, "bad request: "+err.Error())
		return
	}
	var in intent.Intent
	if err := json.Unmarshal([]byte(req.Intent), &in); err != nil {
		fail(w, "intent did not parse: "+err.Error())
		return
	}
	if _, err := intent.Declare(in); err != nil {
		fail(w, err.Error())
		return
	}
	var events []guard.Event
	for i, line := range strings.Split(req.Stream, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev guard.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			fail(w, "stream line is not valid JSON")
			return
		}
		if ev.Seq == 0 {
			ev.Seq = i + 1
		}
		events = append(events, ev)
	}
	session := guard.Run(r.Context(), events, guard.Options{Intent: in, Judge: s.judge()})
	writeJSON(w, map[string]interface{}{"session": session, "judge_active": s.judge() != nil})
}

// --- Samples ----------------------------------------------------------------

func (s *Server) handleSamples(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Which string `json:"which"`
	}
	_ = decode(r, &req)
	writeJSON(w, map[string]string{"content": sampleFor(req.Which)})
}

// judge builds the Layer 3 judge from the environment, or nil (offline).
func (s *Server) judge() verify.Judge {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return verify.NewLLMJudge(analyzer.NewClient(key, "claude-sonnet-4-5"), "claude-sonnet-4-5")
	}
	return nil
}
