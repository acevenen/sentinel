// Package scanner discovers source files in a repository, filters out
// binaries, vendored code, and gitignored paths, and splits large files
// into line-aligned chunks suitable for LLM analysis.
package scanner

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	gitignore "github.com/sabhiram/go-gitignore"
)

// Options controls a scan.
type Options struct {
	// Root is the directory to walk.
	Root string
	// Include restricts the scan to files matching at least one glob
	// (matched against the slash-separated relative path and the base name).
	Include []string
	// Exclude skips files matching any glob.
	Exclude []string
	// MaxChunkBytes is the maximum size of a single chunk sent for analysis.
	MaxChunkBytes int
	// MaxFileBytes is the largest file the scanner will read; bigger files
	// are assumed generated and skipped.
	MaxFileBytes int
}

// DefaultMaxChunkBytes keeps chunks comfortably inside a single model request.
const DefaultMaxChunkBytes = 48 * 1024

// DefaultMaxFileBytes skips files that are almost certainly generated or data.
const DefaultMaxFileBytes = 1 << 20 // 1 MiB

// Chunk is a contiguous, line-aligned slice of one source file.
type Chunk struct {
	// Path is the slash-separated path relative to the scan root.
	Path string
	// Content is the raw source text of this chunk.
	Content string
	// StartLine and EndLine are 1-based, inclusive line numbers within the file.
	StartLine int
	EndLine   int
	// Part and Parts describe this chunk's position when a file is split.
	Part  int
	Parts int
}

// Result is the output of a scan.
type Result struct {
	Chunks []Chunk
	// Files is the number of distinct files that produced chunks.
	Files int
}

// directories that never contain first-party source worth scanning.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, "bower_components": true,
	"dist": true, "build": true, "out": true, ".next": true, ".nuxt": true,
	"target": true, "__pycache__": true, ".venv": true, "venv": true,
	".idea": true, ".vscode": true, ".terraform": true, "coverage": true,
	"testdata_fixtures": true,
}

// extensions treated as scannable source code or configuration.
var sourceExtensions = map[string]bool{
	".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mjs": true, ".cjs": true, ".py": true, ".rb": true, ".php": true,
	".java": true, ".kt": true, ".kts": true, ".scala": true,
	".c": true, ".h": true, ".cpp": true, ".cc": true, ".hpp": true,
	".cs": true, ".rs": true, ".swift": true, ".m": true,
	".sh": true, ".bash": true, ".zsh": true, ".ps1": true, ".psm1": true,
	".sql": true, ".html": true, ".vue": true, ".svelte": true,
	".yaml": true, ".yml": true, ".tf": true, ".env": true,
}

// Scan walks opts.Root and returns analyzable chunks.
func Scan(opts Options) (Result, error) {
	if opts.MaxChunkBytes <= 0 {
		opts.MaxChunkBytes = DefaultMaxChunkBytes
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}

	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return Result{}, fmt.Errorf("resolving %q: %w", opts.Root, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("%s is not a directory", opts.Root)
	}

	// Respect the repository's root .gitignore when present.
	var ign *gitignore.GitIgnore
	if compiled, err := gitignore.CompileIgnoreFile(filepath.Join(root, ".gitignore")); err == nil {
		ign = compiled
	}

	var res Result
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		if d.IsDir() {
			if skipDirs[d.Name()] || (ign != nil && ign.MatchesPath(rel+"/")) {
				return filepath.SkipDir
			}
			return nil
		}

		if !sourceExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		if ign != nil && ign.MatchesPath(rel) {
			return nil
		}
		if !matchesFilters(rel, opts.Include, opts.Exclude) {
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Size() > int64(opts.MaxFileBytes) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", rel, err)
		}
		if isBinary(data) {
			return nil
		}

		parts := chunkContent(string(data), opts.MaxChunkBytes)
		for i, p := range parts {
			res.Chunks = append(res.Chunks, Chunk{
				Path:      rel,
				Content:   p.text,
				StartLine: p.startLine,
				EndLine:   p.endLine,
				Part:      i + 1,
				Parts:     len(parts),
			})
		}
		if len(parts) > 0 {
			res.Files++
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// matchesFilters applies include and exclude globs to a relative path.
func matchesFilters(rel string, include, exclude []string) bool {
	base := filepath.Base(rel)
	for _, pattern := range exclude {
		if globMatch(pattern, rel, base) {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, pattern := range include {
		if globMatch(pattern, rel, base) {
			return true
		}
	}
	return false
}

func globMatch(pattern, rel, base string) bool {
	if ok, err := doublestar.Match(pattern, rel); err == nil && ok {
		return true
	}
	if ok, err := doublestar.Match(pattern, base); err == nil && ok {
		return true
	}
	return false
}

// isBinary reports whether data looks like a binary blob rather than text.
func isBinary(data []byte) bool {
	probe := data
	if len(probe) > 8000 {
		probe = probe[:8000]
	}
	return bytes.IndexByte(probe, 0) != -1
}

type chunkPart struct {
	text      string
	startLine int
	endLine   int
}

// chunkContent splits content into line-aligned pieces of at most maxBytes.
// A single line longer than maxBytes becomes its own oversized chunk rather
// than being split mid-line.
func chunkContent(content string, maxBytes int) []chunkPart {
	if content == "" {
		return nil
	}
	lines := strings.SplitAfter(content, "\n")
	// SplitAfter leaves a trailing empty element when content ends with \n.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var parts []chunkPart
	var buf strings.Builder
	startLine := 1
	lineNo := 0

	flush := func(endLine int) {
		if buf.Len() == 0 {
			return
		}
		parts = append(parts, chunkPart{text: buf.String(), startLine: startLine, endLine: endLine})
		buf.Reset()
		startLine = endLine + 1
	}

	for _, line := range lines {
		lineNo++
		if buf.Len() > 0 && buf.Len()+len(line) > maxBytes {
			flush(lineNo - 1)
		}
		buf.WriteString(line)
	}
	flush(lineNo)
	return parts
}
