package redteam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

type memoryAuditor struct {
	mu     sync.Mutex
	events []tools.AuditEvent
}

func (a *memoryAuditor) Record(_ context.Context, event tools.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func benignSuite() Suite {
	return Suite{
		Name:         "canary",
		RequestField: "prompt",
		Probes: []Probe{{
			ID: "canary-1", CategoryID: "PIT-I-16", Delivery: DeliveryDirect,
			Content: "operator-owned benign canary", FailIfResponseContains: []string{"canary-accepted"},
		}},
	}
}

func TestRunnerLocalTargetAndNoContentInAudit(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls++
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["prompt"] == "" {
			t.Error("missing prompt request field")
		}
		_, _ = w.Write([]byte(`{"answer":"canary-accepted"}`))
	}))
	defer server.Close()

	taxonomy, err := Core()
	if err != nil {
		t.Fatal(err)
	}
	auditor := &memoryAuditor{}
	runner := Runner{
		Guard: authz.Policy{
			Scope:                 authz.NewScope([]string{server.URL}, nil),
			AuthorizationAsserted: true,
		},
		Auditor: auditor, Client: server.Client(), Taxonomy: taxonomy,
	}
	report, err := runner.Run(context.Background(), benignSuite(), RunOptions{
		Target: server.URL, Operator: "tester", Mode: TargetBlackBox, Approved: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(report.Results) != 1 || report.Results[0].Status != StatusFailed {
		t.Fatalf("report = %+v, calls = %d", report, calls)
	}
	for _, event := range auditor.events {
		encoded, _ := json.Marshal(event)
		if strings.Contains(string(encoded), "operator-owned benign canary") {
			t.Fatal("audit log contains probe content")
		}
	}
}

func TestRunnerDryRunAndAuthorizationRefusal(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	taxonomy, _ := Core()
	auditor := &memoryAuditor{}

	runner := Runner{
		Guard: authz.Policy{
			Scope:                 authz.NewScope([]string{server.URL}, nil),
			AuthorizationAsserted: true,
		},
		Auditor: auditor, Client: server.Client(), Taxonomy: taxonomy,
	}
	report, err := runner.Run(context.Background(), benignSuite(), RunOptions{
		Target: server.URL, Operator: "tester", Mode: TargetBlackBox, Approved: true, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || report.Results[0].Status != StatusPlanned {
		t.Fatalf("dry-run report = %+v, calls = %d", report, calls)
	}

	runner.Guard = authz.Policy{Scope: authz.NewScope([]string{server.URL}, nil)}
	if _, err := runner.Run(context.Background(), benignSuite(), RunOptions{
		Target: server.URL, Operator: "tester", Mode: TargetBlackBox, Approved: true,
	}); !errors.Is(err, authz.ErrAuthorizationRequired) {
		t.Fatalf("refusal error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("authorization refusal made %d HTTP calls", calls)
	}
}

func TestRunnerRequiresApprovalAndSkipsWhiteBox(t *testing.T) {
	taxonomy, _ := Core()
	runner := Runner{Taxonomy: taxonomy}
	if _, err := runner.Run(context.Background(), benignSuite(), RunOptions{Mode: TargetBlackBox}); err == nil {
		t.Fatal("runner accepted an unapproved suite")
	}
}
