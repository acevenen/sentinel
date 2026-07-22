package hunt

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

// recordingDoer records requests it receives and returns a canned response.
type recordingDoer struct {
	calls    atomic.Int64
	lastAuth string
	status   int
	body     string
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	d.lastAuth = req.Header.Get("Authorization")
	status := d.status
	if status == 0 {
		status = 200
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     http.Header{},
	}, nil
}

func testGate() *ScopeGate {
	return gate([]string{"api.example.com"}, []string{"admin.example.com"})
}

func TestClientRefusesOutOfScope(t *testing.T) {
	doer := &recordingDoer{}
	c := NewClient(doer, testGate(), 1000)

	_, err := c.Get(context.Background(), "GET", "https://evil.example/x", "Authorization", "t")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope, got %v", err)
	}
	if doer.calls.Load() != 0 {
		t.Errorf("out-of-scope request must not reach the transport; calls=%d", doer.calls.Load())
	}
}

func TestClientRefusesExplicitOutOfScopeHost(t *testing.T) {
	doer := &recordingDoer{}
	c := NewClient(doer, testGate(), 1000)
	// admin.example.com is explicitly out of scope even though example.com is in.
	_, err := c.Get(context.Background(), "GET", "https://admin.example.com/x", "Authorization", "t")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope for explicitly out-of-scope host, got %v", err)
	}
	if doer.calls.Load() != 0 {
		t.Errorf("request must not be sent; calls=%d", doer.calls.Load())
	}
}

func TestClientRefusesWriteMethod(t *testing.T) {
	doer := &recordingDoer{}
	c := NewClient(doer, testGate(), 1000)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if _, err := c.Get(context.Background(), m, "https://api.example.com/x", "", ""); !errors.Is(err, ErrWriteMethod) {
			t.Errorf("%s should be refused as a write method, got %v", m, err)
		}
	}
	if doer.calls.Load() != 0 {
		t.Errorf("write methods must not be sent; calls=%d", doer.calls.Load())
	}
}

func TestClientSendsInScopeWithAuth(t *testing.T) {
	doer := &recordingDoer{status: 200, body: "ok"}
	c := NewClient(doer, testGate(), 1000)

	resp, err := c.Get(context.Background(), "GET", "https://api.example.com/v1/orders/1", "Authorization", "Bearer xyz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || string(resp.Body) != "ok" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if doer.lastAuth != "Bearer xyz" {
		t.Errorf("auth header not attached: %q", doer.lastAuth)
	}
}

func TestClientRateLimits(t *testing.T) {
	doer := &recordingDoer{status: 200}
	c := NewClient(doer, testGate(), 50) // 50 rps => 20ms min interval

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.Get(context.Background(), "GET", "https://api.example.com/x", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	// 3 requests at 20ms spacing => at least ~40ms for the 2 gaps.
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Errorf("rate limiter did not pace requests: %v", elapsed)
	}
}
