package analyzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acevenen/sentinel/internal/scanner"
)

func makeChunks(n int) []scanner.Chunk {
	chunks := make([]scanner.Chunk, n)
	for i := range chunks {
		chunks[i] = scanner.Chunk{
			Path:      fmt.Sprintf("file%d.go", i),
			Content:   "package main\n",
			StartLine: 1,
			EndLine:   1,
			Part:      1,
			Parts:     1,
		}
	}
	return chunks
}

func okResponse(findingsJSON string) *http.Response {
	body := fmt.Sprintf(`{"content":[{"type":"text","text":%q}],"stop_reason":"end_turn"}`, findingsJSON)
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestRunCollectsFindingsFromAllChunks(t *testing.T) {
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		return okResponse(`[{"file":"x","line":1,"severity":"high","title":"issue"}]`), nil
	})
	a := New(newTestClient(doer), 4)

	findings, errs := a.Run(context.Background(), makeChunks(10), nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(findings) != 10 {
		t.Fatalf("got %d findings, want 10", len(findings))
	}
}

func TestRunRespectsConcurrencyLimit(t *testing.T) {
	const limit = 3
	var current, peak atomic.Int64
	var mu sync.Mutex

	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		now := current.Add(1)
		mu.Lock()
		if now > peak.Load() {
			peak.Store(now)
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return okResponse("[]"), nil
	})

	a := New(newTestClient(doer), limit)
	_, errs := a.Run(context.Background(), makeChunks(12), nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if peak.Load() > limit {
		t.Errorf("peak concurrency %d exceeded limit %d", peak.Load(), limit)
	}
}

func TestRunContinuesPastPerChunkFailures(t *testing.T) {
	var calls atomic.Int64
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1)%2 == 0 {
			return &http.Response{
				StatusCode: 400,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"invalid_request_error","message":"bad"}}`)),
			}, nil
		}
		return okResponse(`[{"file":"x","line":1,"severity":"low","title":"t"}]`), nil
	})

	a := New(newTestClient(doer), 1)
	findings, errs := a.Run(context.Background(), makeChunks(6), nil)
	if len(findings) != 3 {
		t.Errorf("got %d findings, want 3", len(findings))
	}
	if len(errs) != 3 {
		t.Errorf("got %d errors, want 3", len(errs))
	}
}

func TestRunHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		return okResponse("[]"), nil
	})
	a := New(newTestClient(doer), 2)

	start := time.Now()
	findings, errs := a.Run(ctx, makeChunks(100), nil)
	if time.Since(start) > 5*time.Second {
		t.Fatal("Run did not return promptly after cancellation")
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings from canceled run", len(findings))
	}
	if len(errs) == 0 {
		t.Error("expected cancellation errors")
	}
}

func TestRunReportsProgress(t *testing.T) {
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		return okResponse("[]"), nil
	})
	a := New(newTestClient(doer), 2)

	var mu sync.Mutex
	var updates []int
	a.Run(context.Background(), makeChunks(5), func(done, total int) {
		mu.Lock()
		updates = append(updates, done)
		mu.Unlock()
		if total != 5 {
			t.Errorf("total = %d, want 5", total)
		}
	})

	if len(updates) != 5 {
		t.Fatalf("got %d progress updates, want 5", len(updates))
	}
}

func TestRunSortsFindingsBySeverity(t *testing.T) {
	var calls atomic.Int64
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		sev := []string{"low", "critical", "medium"}[calls.Add(1)-1]
		return okResponse(fmt.Sprintf(`[{"file":"x","line":1,"severity":"%s","title":"t"}]`, sev)), nil
	})

	a := New(newTestClient(doer), 1)
	findings, _ := a.Run(context.Background(), makeChunks(3), nil)
	if len(findings) != 3 {
		t.Fatalf("got %d findings", len(findings))
	}
	if findings[0].Severity != SeverityCritical || findings[2].Severity != SeverityLow {
		t.Errorf("findings not sorted worst-first: %+v", findings)
	}
}

func TestBuildUserPromptNumbersLines(t *testing.T) {
	chunk := scanner.Chunk{
		Path:      "a/b.go",
		Content:   "first\nsecond\n",
		StartLine: 41,
		EndLine:   42,
		Part:      2,
		Parts:     3,
	}
	prompt := buildUserPrompt(chunk)

	for _, want := range []string{"File: a/b.go", "part 2 of 3", "41 | first", "42 | second"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, prompt)
		}
	}
}
