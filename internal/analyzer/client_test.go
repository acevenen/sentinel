package analyzer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubDoer returns canned responses in order, then repeats the last one.
type stubDoer struct {
	responses []stubResponse
	calls     atomic.Int64
}

type stubResponse struct {
	status  int
	body    string
	headers http.Header
	err     error
}

func (s *stubDoer) Do(req *http.Request) (*http.Response, error) {
	n := int(s.calls.Add(1)) - 1
	if n >= len(s.responses) {
		n = len(s.responses) - 1
	}
	r := s.responses[n]
	if r.err != nil {
		return nil, r.err
	}
	headers := r.headers
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{
		StatusCode: r.status,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

const okBody = `{"content":[{"type":"text","text":"[]"}],"stop_reason":"end_turn"}`

func newTestClient(doer Doer, opts ...Option) *Client {
	base := []Option{
		WithHTTPClient(doer),
		withSleep(func(ctx context.Context, d time.Duration) error { return ctx.Err() }),
	}
	return NewClient("test-key", "test-model", append(base, opts...)...)
}

func TestCompleteSuccess(t *testing.T) {
	doer := &stubDoer{responses: []stubResponse{{status: 200, body: okBody}}}
	c := newTestClient(doer)

	text, err := c.complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if text != "[]" {
		t.Errorf("text = %q, want %q", text, "[]")
	}
	if doer.calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", doer.calls.Load())
	}
}

func TestCompleteRetriesRateLimitThenSucceeds(t *testing.T) {
	doer := &stubDoer{responses: []stubResponse{
		{status: 429, body: `{"error":{"type":"rate_limit_error","message":"slow down"}}`},
		{status: 529, body: `{"error":{"type":"overloaded_error","message":"busy"}}`},
		{status: 200, body: okBody},
	}}
	c := newTestClient(doer)

	if _, err := c.complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if doer.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3 (two retries)", doer.calls.Load())
	}
}

func TestCompleteRetriesNetworkErrors(t *testing.T) {
	doer := &stubDoer{responses: []stubResponse{
		{err: errors.New("connection reset")},
		{status: 200, body: okBody},
	}}
	c := newTestClient(doer)

	if _, err := c.complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if doer.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", doer.calls.Load())
	}
}

func TestCompleteDoesNotRetryClientErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"bad request", 400},
		{"unauthorized", 401},
		{"forbidden", 403},
		{"not found", 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doer := &stubDoer{responses: []stubResponse{
				{status: tt.status, body: `{"error":{"type":"invalid_request_error","message":"nope"}}`},
			}}
			c := newTestClient(doer)

			_, err := c.complete(context.Background(), "s", "u")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("want *APIError, got %v", err)
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("status = %d, want %d", apiErr.StatusCode, tt.status)
			}
			if doer.calls.Load() != 1 {
				t.Errorf("calls = %d, want 1 (no retries)", doer.calls.Load())
			}
		})
	}
}

func TestCompleteGivesUpAfterMaxRetries(t *testing.T) {
	doer := &stubDoer{responses: []stubResponse{
		{status: 500, body: `{"error":{"type":"api_error","message":"boom"}}`},
	}}
	c := newTestClient(doer, WithMaxRetries(2))

	_, err := c.complete(context.Background(), "s", "u")
	if err == nil {
		t.Fatal("want error after exhausting retries")
	}
	if doer.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3 (1 + 2 retries)", doer.calls.Load())
	}
	if !strings.Contains(err.Error(), "giving up after 3 attempts") {
		t.Errorf("error should mention attempts: %v", err)
	}
}

func TestCompleteHonorsContextCancellation(t *testing.T) {
	doer := &stubDoer{responses: []stubResponse{
		{status: 500, body: `{}`},
	}}
	c := newTestClient(doer)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.complete(ctx, "s", "u")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestCompleteSendsCorrectHeaders(t *testing.T) {
	var captured *http.Request
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		captured = req
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(okBody)),
		}, nil
	})
	c := newTestClient(doer)

	if _, err := c.complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if got := captured.Header.Get("x-api-key"); got != "test-key" {
		t.Errorf("x-api-key = %q", got)
	}
	if got := captured.Header.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("anthropic-version = %q", got)
	}
	if got := captured.Header.Get("content-type"); got != "application/json" {
		t.Errorf("content-type = %q", got)
	}
	if captured.URL.Path != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", captured.URL.Path)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestExtractText(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{"single block", okBody, "[]", false},
		{"multiple blocks joined", `{"content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}`, "ab", false},
		{"non-text blocks ignored", `{"content":[{"type":"thinking","text":"x"},{"type":"text","text":"y"}]}`, "y", false},
		{"empty content errors", `{"content":[],"stop_reason":"end_turn"}`, "", true},
		{"invalid json errors", `{{{`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractText([]byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("text = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBackoffDelayGrowsAndHonorsRetryAfter(t *testing.T) {
	small := backoffDelay(1, nil)
	if small < baseBackoff/2 || small > baseBackoff {
		t.Errorf("attempt 1 delay %v outside [%v, %v]", small, baseBackoff/2, baseBackoff)
	}

	big := backoffDelay(10, nil)
	if big > maxBackoff {
		t.Errorf("delay %v exceeds cap %v", big, maxBackoff)
	}

	retryErr := &retryableError{apiErr: &APIError{StatusCode: 429}, retryAfter: time.Minute}
	if got := backoffDelay(1, retryErr); got != time.Minute {
		t.Errorf("Retry-After not honored: got %v, want 1m", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	h := http.Header{}
	if got := parseRetryAfter(h); got != 0 {
		t.Errorf("empty header: got %v", got)
	}
	h.Set("Retry-After", "7")
	if got := parseRetryAfter(h); got != 7*time.Second {
		t.Errorf("got %v, want 7s", got)
	}
	h.Set("Retry-After", "not-a-number")
	if got := parseRetryAfter(h); got != 0 {
		t.Errorf("invalid header: got %v", got)
	}
}
