package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a file (and parent dirs) under root.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func chunkPaths(res Result) []string {
	seen := map[string]bool{}
	var paths []string
	for _, c := range res.Chunks {
		if !seen[c.Path] {
			seen[c.Path] = true
			paths = append(paths, c.Path)
		}
	}
	return paths
}

func TestScanFiltering(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		setup func(t *testing.T, root string)
		opts  func(root string) Options
		want  []string
	}{
		{
			name: "skips non-source, vendored dirs, and binaries",
			files: map[string]string{
				"main.go":            "package main\n",
				"README.md":          "# readme\n",
				"node_modules/x.js":  "var x = 1;\n",
				"vendor/dep/dep.go":  "package dep\n",
				".git/config.yaml":   "core: true\n",
				"blob.go":            "package blob\n\x00\x01\x02binary",
				"nested/app/util.py": "def f():\n    pass\n",
			},
			opts: func(root string) Options { return Options{Root: root} },
			want: []string{"main.go", "nested/app/util.py"},
		},
		{
			name: "respects root gitignore",
			files: map[string]string{
				".gitignore":       "ignored.go\ngenerated/\n",
				"main.go":          "package main\n",
				"ignored.go":       "package main\n",
				"generated/gen.go": "package gen\n",
			},
			opts: func(root string) Options { return Options{Root: root} },
			want: []string{"main.go"},
		},
		{
			name: "include globs restrict the scan",
			files: map[string]string{
				"a.go":         "package a\n",
				"b.js":         "let b = 1;\n",
				"deep/c.go":    "package c\n",
				"deep/d.ts":    "const d = 1;\n",
				"deep/e/f.go":  "package f\n",
				"deep/e/g.py":  "g = 1\n",
				"deep/e/h.tsx": "const h = 1;\n",
			},
			opts: func(root string) Options { return Options{Root: root, Include: []string{"*.go"}} },
			want: []string{"a.go", "deep/c.go", "deep/e/f.go"},
		},
		{
			name: "exclude globs win over include",
			files: map[string]string{
				"keep.go":      "package keep\n",
				"skip/drop.go": "package drop\n",
			},
			opts: func(root string) Options {
				return Options{Root: root, Include: []string{"*.go"}, Exclude: []string{"skip/**"}}
			},
			want: []string{"keep.go"},
		},
		{
			name: "oversized files are skipped",
			files: map[string]string{
				"small.go": "package small\n",
			},
			setup: func(t *testing.T, root string) {
				writeFile(t, root, "huge.go", "package huge\n"+strings.Repeat("// padding line\n", 200))
			},
			opts: func(root string) Options {
				return Options{Root: root, MaxFileBytes: 64}
			},
			want: []string{"small.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, content := range tt.files {
				writeFile(t, root, rel, content)
			}
			if tt.setup != nil {
				tt.setup(t, root)
			}

			res, err := Scan(tt.opts(root))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}

			got := chunkPaths(res)
			if len(got) != len(tt.want) {
				t.Fatalf("scanned files = %v, want %v", got, tt.want)
			}
			wantSet := map[string]bool{}
			for _, w := range tt.want {
				wantSet[w] = true
			}
			for _, g := range got {
				if !wantSet[g] {
					t.Errorf("unexpected file scanned: %s (want %v)", g, tt.want)
				}
			}
			if res.Files != len(tt.want) {
				t.Errorf("Files = %d, want %d", res.Files, len(tt.want))
			}
		})
	}
}

func TestScanErrors(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		if _, err := Scan(Options{Root: filepath.Join(t.TempDir(), "nope")}); err == nil {
			t.Fatal("want error for missing directory")
		}
	})
	t.Run("root is a file", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "f.go", "package f\n")
		if _, err := Scan(Options{Root: filepath.Join(root, "f.go")}); err == nil {
			t.Fatal("want error when root is a file")
		}
	})
}

func TestChunking(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		maxBytes  int
		wantParts int
	}{
		{"empty file", "", 100, 0},
		{"fits in one chunk", "line one\nline two\n", 100, 1},
		{"splits on line boundaries", strings.Repeat("0123456789\n", 10), 34, 4},
		{"single oversized line kept whole", strings.Repeat("x", 500) + "\n", 100, 1},
		{"no trailing newline", "a\nb\nc", 100, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := chunkContent(tt.content, tt.maxBytes)
			if len(parts) != tt.wantParts {
				t.Fatalf("got %d parts, want %d", len(parts), tt.wantParts)
			}

			// Content must round-trip exactly.
			var sb strings.Builder
			for _, p := range parts {
				sb.WriteString(p.text)
			}
			if sb.String() != tt.content {
				t.Errorf("chunks do not reassemble to original content")
			}

			// Line ranges must be contiguous starting at 1.
			next := 1
			for _, p := range parts {
				if p.startLine != next {
					t.Errorf("chunk starts at line %d, want %d", p.startLine, next)
				}
				if p.endLine < p.startLine {
					t.Errorf("chunk end %d before start %d", p.endLine, p.startLine)
				}
				next = p.endLine + 1
			}
		})
	}
}

func TestChunkLineNumbersMatchContent(t *testing.T) {
	content := strings.Repeat("0123456789\n", 100) // 100 lines, 1100 bytes
	parts := chunkContent(content, 300)
	if len(parts) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(parts))
	}
	for _, p := range parts {
		gotLines := strings.Count(p.text, "\n")
		wantLines := p.endLine - p.startLine + 1
		if gotLines != wantLines {
			t.Errorf("chunk %d-%d contains %d lines, want %d", p.startLine, p.endLine, gotLines, wantLines)
		}
	}
}
