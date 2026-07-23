// Package webui serves Sentinel's local desktop UI: a single-page app, embedded
// in the binary, that drives the same scan/guard/evaluate/hunt engine in-process
// (no shelling out, no duplicated logic). It binds to loopback only and gates
// its API with a per-launch token so no other page on the machine can drive it.
package webui

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets/*
var assets embed.FS

// Server is the local UI HTTP handler.
type Server struct {
	mux     *http.ServeMux
	token   string
	index   []byte
	version string
}

// New builds a server. version is shown in the UI footer.
func New(version string) (*Server, error) {
	raw, err := assets.ReadFile("assets/index.html")
	if err != nil {
		return nil, err
	}
	token := randomToken()
	s := &Server{
		mux:     http.NewServeMux(),
		token:   token,
		index:   []byte(strings.ReplaceAll(string(raw), "__SENTINEL_TOKEN__", token)),
		version: version,
	}
	s.routes()
	return s, nil
}

// Token is the per-launch API token the page must send on every API call.
func (s *Server) Token() string { return s.token }

// Handler returns the HTTP handler for the UI.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	static, _ := fs.Sub(assets, "assets")
	fileServer := http.FileServer(http.FS(static))

	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(s.index)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	// API endpoints — all gated by the per-launch token.
	s.mux.HandleFunc("/api/hunt/import", s.guarded(s.handleHuntImport))
	s.mux.HandleFunc("/api/hunt/plan", s.guarded(s.handleHuntPlan))
	s.mux.HandleFunc("/api/hunt/run", s.guarded(s.handleHuntRun))
	s.mux.HandleFunc("/api/evaluate", s.guarded(s.handleEvaluate))
	s.mux.HandleFunc("/api/guard", s.guarded(s.handleGuard))
	s.mux.HandleFunc("/api/samples", s.guarded(s.handleSamples))
}

// guarded wraps an API handler with the token check. The token is set on the
// page at launch and sent as X-Sentinel-Token, so a different local page or a
// remote site cannot drive the API (defense against DNS-rebinding / CSRF).
func (s *Server) guarded(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sentinel-Token") != s.token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "sentinel-local"
	}
	return hex.EncodeToString(b)
}
