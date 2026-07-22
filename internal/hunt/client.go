package hunt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Doer abstracts *http.Client so the engine can be tested with a mock transport
// and no real network calls.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// DefaultTransport is the real HTTP client used against live authorized targets.
func DefaultTransport() Doer {
	return &http.Client{Timeout: 30 * time.Second}
}

// Sentinel errors returned by the client's guardrails.
var (
	// ErrOutOfScope means a request targeted a host outside the program scope
	// and was refused before being sent.
	ErrOutOfScope = errors.New("host is out of program scope")
	// ErrWriteMethod means a non-read-only method was refused (hunt never
	// mutates target data).
	ErrWriteMethod = errors.New("method is not read-only")
)

// Client wraps a Doer with the hunt guardrails: it refuses out-of-scope hosts
// and non-read-only methods before anything is sent, and paces requests to the
// program's rate limit. Every outbound request in hunt goes through it.
type Client struct {
	doer     Doer
	gate     *ScopeGate
	interval time.Duration

	mu   sync.Mutex
	last time.Time
}

// NewClient builds a guarded client. rps <= 0 falls back to the default rate.
func NewClient(doer Doer, gate *ScopeGate, rps float64) *Client {
	if rps <= 0 {
		rps = DefaultRateLimitRPS
	}
	return &Client{
		doer:     doer,
		gate:     gate,
		interval: time.Duration(float64(time.Second) / rps),
	}
}

// Response is the minimal, fully-read result the engine compares. Reading the
// body here keeps the differential logic simple and deterministic.
type Response struct {
	Status int
	Body   []byte
}

// Get issues a read-only request to rawURL with the given identity header and
// returns the response. It refuses out-of-scope hosts and non-read methods and
// respects the rate limit. The request is never sent if a guardrail trips.
func (c *Client) Get(ctx context.Context, method, rawURL string, header, value string) (Response, error) {
	if !readOnlyMethod(method) {
		return Response{}, fmt.Errorf("%w: %s", ErrWriteMethod, method)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), rawURL, nil)
	if err != nil {
		return Response{}, err
	}
	if !c.gate.InScope(req.URL.Hostname()) {
		return Response{}, fmt.Errorf("%w: %s", ErrOutOfScope, req.URL.Hostname())
	}
	if header != "" {
		req.Header.Set(header, value)
	}

	c.wait()

	resp, err := c.doer.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return Response{}, fmt.Errorf("reading response: %w", err)
	}
	return Response{Status: resp.StatusCode, Body: body}, nil
}

// wait enforces the minimum interval between requests.
func (c *Client) wait() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.last.IsZero() {
		if elapsed := now.Sub(c.last); elapsed < c.interval {
			time.Sleep(c.interval - elapsed)
		}
	}
	c.last = time.Now()
}
