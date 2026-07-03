package analyzer

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/acevenen/sentinel/internal/scanner"
)

// Analyzer fans chunks out to the Anthropic API with bounded concurrency.
type Analyzer struct {
	client      *Client
	concurrency int
}

// New builds an Analyzer around a Client. Concurrency below 1 is coerced to 1.
func New(client *Client, concurrency int) *Analyzer {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Analyzer{client: client, concurrency: concurrency}
}

// Run analyzes every chunk using a semaphore-bounded worker pool. It honors
// context cancellation (Ctrl+C) and keeps going when individual chunks fail,
// returning the findings it collected alongside any per-chunk errors.
func (a *Analyzer) Run(ctx context.Context, chunks []scanner.Chunk, onProgress func(done, total int)) ([]Finding, []error) {
	var (
		mu       sync.Mutex
		findings []Finding
		errs     []error
		done     int
	)

	sem := make(chan struct{}, a.concurrency)
	var wg sync.WaitGroup

	for _, chunk := range chunks {
		// Check cancellation explicitly: a select between ctx.Done() and the
		// semaphore would pick randomly when both are ready.
		if err := ctx.Err(); err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("canceled before analyzing %s: %w", chunk.Path, err))
			mu.Unlock()
			continue
		}

		select {
		case <-ctx.Done():
			mu.Lock()
			errs = append(errs, fmt.Errorf("canceled before analyzing %s: %w", chunk.Path, ctx.Err()))
			mu.Unlock()
		case sem <- struct{}{}:
			wg.Add(1)
			go func(chunk scanner.Chunk) {
				defer wg.Done()
				defer func() { <-sem }()

				result, err := a.analyzeChunk(ctx, chunk)

				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, fmt.Errorf("%s (lines %d-%d): %w", chunk.Path, chunk.StartLine, chunk.EndLine, err))
				} else {
					findings = append(findings, result...)
				}
				done++
				if onProgress != nil {
					onProgress(done, len(chunks))
				}
			}(chunk)
		}
	}
	wg.Wait()

	sortFindings(findings)
	return findings, errs
}

func (a *Analyzer) analyzeChunk(ctx context.Context, chunk scanner.Chunk) ([]Finding, error) {
	text, err := a.client.complete(ctx, systemPrompt, buildUserPrompt(chunk))
	if err != nil {
		return nil, err
	}
	return parseFindings(text, chunk), nil
}

// sortFindings orders results by severity (worst first), then file, then line.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
}
