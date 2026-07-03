package analyzer

import (
	"testing"

	"github.com/acevenen/sentinel/internal/scanner"
)

var testChunk = scanner.Chunk{
	Path:      "src/app.go",
	StartLine: 1,
	EndLine:   100,
	Part:      1,
	Parts:     1,
}

func TestParseFindings(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{
			name: "clean JSON array",
			raw:  `[{"file":"src/app.go","line":10,"severity":"high","category":"CWE-89","title":"SQL injection","description":"d","recommendation":"r"}]`,
			want: 1,
		},
		{
			name: "markdown fenced",
			raw:  "```json\n[{\"file\":\"a\",\"line\":5,\"severity\":\"low\",\"title\":\"t\"}]\n```",
			want: 1,
		},
		{
			name: "prose around the array",
			raw:  `Here are the findings: [{"file":"a","line":2,"severity":"medium","title":"t"}] Hope that helps!`,
			want: 1,
		},
		{
			name: "empty array",
			raw:  `[]`,
			want: 0,
		},
		{
			name: "empty array in fences",
			raw:  "```json\n[]\n```",
			want: 0,
		},
		{
			name: "garbage response",
			raw:  `I cannot analyze this code.`,
			want: 0,
		},
		{
			name: "malformed JSON",
			raw:  `[{"file": "a", "line": }]`,
			want: 0,
		},
		{
			name: "invalid severity skipped",
			raw:  `[{"file":"a","line":1,"severity":"banana","title":"t"},{"file":"a","line":2,"severity":"high","title":"kept"}]`,
			want: 1,
		},
		{
			name: "missing title skipped",
			raw:  `[{"file":"a","line":1,"severity":"high","title":"  "},{"file":"a","line":2,"severity":"high","title":"kept"}]`,
			want: 1,
		},
		{
			name: "line as string",
			raw:  `[{"file":"a","line":"42","severity":"critical","title":"t"}]`,
			want: 1,
		},
		{
			name: "line as float",
			raw:  `[{"file":"a","line":12.0,"severity":"low","title":"t"}]`,
			want: 1,
		},
		{
			name: "severity case-insensitive",
			raw:  `[{"file":"a","line":1,"severity":"HIGH","title":"t"}]`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFindings(tt.raw, testChunk)
			if len(got) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tt.want, got)
			}
		})
	}
}

func TestParseFindingsNormalization(t *testing.T) {
	chunk := scanner.Chunk{Path: "pkg/db.go", StartLine: 50, EndLine: 80}

	raw := `[
		{"file":"totally/wrong/path.go","line":60,"severity":"HIGH","category":" CWE-89 ","title":" SQLi ","description":" d ","recommendation":" r "},
		{"file":"x","line":5,"severity":"low","title":"below range"},
		{"file":"x","line":9999,"severity":"low","title":"above range"},
		{"file":"x","severity":"low","title":"no line at all"}
	]`

	got := parseFindings(raw, chunk)
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4", len(got))
	}

	first := got[0]
	if first.File != "pkg/db.go" {
		t.Errorf("file not pinned to chunk path: %q", first.File)
	}
	if first.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", first.Severity)
	}
	if first.Category != "CWE-89" || first.Title != "SQLi" || first.Description != "d" || first.Recommendation != "r" {
		t.Errorf("fields not trimmed: %+v", first)
	}
	if first.Line != 60 {
		t.Errorf("line = %d, want 60", first.Line)
	}

	if got[1].Line != 50 {
		t.Errorf("below-range line = %d, want clamped to 50", got[1].Line)
	}
	if got[2].Line != 80 {
		t.Errorf("above-range line = %d, want clamped to 80", got[2].Line)
	}
	if got[3].Line != 50 {
		t.Errorf("missing line = %d, want chunk start 50", got[3].Line)
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"low", SeverityLow, true},
		{"MEDIUM", SeverityMedium, true},
		{" High ", SeverityHigh, true},
		{"critical", SeverityCritical, true},
		{"", "", false},
		{"severe", "", false},
	}
	for _, tt := range tests {
		got, ok := ParseSeverity(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("ParseSeverity(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	ordered := SeverityCritical.Rank() > SeverityHigh.Rank() &&
		SeverityHigh.Rank() > SeverityMedium.Rank() &&
		SeverityMedium.Rank() > SeverityLow.Rank() &&
		SeverityLow.Rank() > Severity("bogus").Rank()
	if !ordered {
		t.Fatal("severity ranks are not strictly ordered")
	}
}
