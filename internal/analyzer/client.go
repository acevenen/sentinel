// Package analyzer sends source chunks to the Anthropic Messages API and
// parses the structured findings Claude returns. It never persists the API
// key and never asks the model for exploit code.
package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL   = "https://api.anthropic.com"
	apiVersion       = "2023-06-01"
	defaultMaxTokens = 4096
	defaultRetries   = 4
	baseBackoff      = 500 * time.Millisecond
	maxBackoff       = 16 * time.Second
)

// Doer abstracts *http.Client so tests can stub the transport.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is a minimal Anthropic Messages API client with retry.
type Client struct {
	httpClient Doer
	apiKey     string
	model      string
	baseURL    string
	maxTokens  int
	maxRetries int
	// sleep is swappable in tests so retries don't wall-clock wait.
	sleep func(ctx context.Context, d time.Duration) error
}

// Option customizes a Client.
type Option func(*Client)

// WithHTTPClient replaces the underlying HTTP transport.
func WithHTTPClient(d Doer) Option { return func(c *Client) { c.httpClient = d } }

// WithBaseURL points the client at a different API host (used in tests).
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") } }

// WithMaxRetries sets how many times a retryable failure is reattempted.
func WithMaxRetries(n int) Option { return func(c *Client) { c.maxRetries = n } }

// WithMaxTokens caps the model's response length.
func WithMaxTokens(n int) Option { return func(c *Client) { c.maxTokens = n } }

// withSleep is test-only: it replaces the backoff timer.
func withSleep(fn func(ctx context.Context, d time.Duration) error) Option {
	return func(c *Client) { c.sleep = fn }
}

// NewClient builds a Client for the given API key and model.
func NewClient(apiKey, model string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 120 * time.Second},
		apiKey:     apiKey,
		model:      model,
		baseURL:    defaultBaseURL,
		maxTokens:  defaultMaxTokens,
		maxRetries: defaultRetries,
		sleep: func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type apiErrorBody struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// APIError is a non-retryable error response from the Anthropic API.
type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("anthropic api error (HTTP %d, %s): %s", e.StatusCode, e.Type, e.Message)
}

// complete sends one system+user exchange and returns the text response,
// retrying 429/5xx/529 and transport errors with exponential backoff + jitter.
func (c *Client) complete(ctx context.Context, system, user string) (string, error) {
	payload, err := json.Marshal(messagesRequest{
		Model:     c.model,
		MaxTokens: c.maxTokens,
		System:    system,
		Messages:  []message{{Role: "user", Content: user}},
	})
	if err != nil {
		return "", fmt.Errorf("encoding request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, backoffDelay(attempt, lastErr)); err != nil {
				return "", err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("x-api-key", c.apiKey)
		req.Header.Set("anthropic-version", apiVersion)
		req.Header.Set("content-type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("reading response: %w", readErr)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return extractText(body)
		}

		var errBody apiErrorBody
		_ = json.Unmarshal(body, &errBody)
		apiErr := &APIError{StatusCode: resp.StatusCode, Type: errBody.Error.Type, Message: errBody.Error.Message}

		if !retryable(resp.StatusCode) {
			return "", apiErr
		}
		lastErr = &retryableError{apiErr: apiErr, retryAfter: parseRetryAfter(resp.Header)}
	}
	return "", fmt.Errorf("giving up after %d attempts: %w", c.maxRetries+1, lastErr)
}

func extractText(body []byte) (string, error) {
	var mr messagesResponse
	if err := json.Unmarshal(body, &mr); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	var sb strings.Builder
	for _, block := range mr.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("response contained no text (stop_reason=%s)", mr.StopReason)
	}
	return sb.String(), nil
}

// retryable reports whether a status code is worth reattempting:
// 429 (rate limit), 5xx (server errors), and 529 (overloaded).
func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

type retryableError struct {
	apiErr     *APIError
	retryAfter time.Duration
}

func (e *retryableError) Error() string { return e.apiErr.Error() }
func (e *retryableError) Unwrap() error { return e.apiErr }

// backoffDelay computes exponential backoff with full jitter, honoring a
// Retry-After header when the server provided one.
func backoffDelay(attempt int, lastErr error) time.Duration {
	delay := baseBackoff << (attempt - 1)
	if delay > maxBackoff {
		delay = maxBackoff
	}
	// Full jitter: uniform in [delay/2, delay].
	delay = delay/2 + time.Duration(rand.Int63n(int64(delay/2)+1)) //nolint:gosec // jitter needs no crypto rand

	var re *retryableError
	if errors.As(lastErr, &re) && re.retryAfter > delay {
		delay = re.retryAfter
	}
	return delay
}

func parseRetryAfter(h http.Header) time.Duration {
	raw := h.Get("Retry-After")
	if raw == "" {
		return 0
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}
