package tools_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
	"github.com/acevenen/sentinel/internal/tools/aircrack"
	"github.com/acevenen/sentinel/internal/tools/hashcat"
	"github.com/acevenen/sentinel/internal/tools/hping"
	"github.com/acevenen/sentinel/internal/tools/kali"
	"github.com/acevenen/sentinel/internal/tools/metasploit"
	"github.com/acevenen/sentinel/internal/tools/setoolkit"
	"github.com/acevenen/sentinel/internal/tools/skipfish"
	"github.com/acevenen/sentinel/internal/tools/sqlmap"
	"github.com/acevenen/sentinel/internal/tools/tshark"
)

type discardExecutor struct{}

func (discardExecutor) Execute(context.Context, tools.Command) (tools.Execution, error) {
	return tools.Execution{}, nil
}

type auditCollector struct {
	events []tools.AuditEvent
}

func (a *auditCollector) Record(_ context.Context, event tools.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

type adapterFactory func(authz.Guardrail, tools.Auditor, tools.Executor, ...tools.CommandAdapterOption) tools.Tool

func TestAdaptersPreflightAndDryRun(t *testing.T) {
	tests := []struct {
		name    string
		factory adapterFactory
		target  string
		args    []string
		want    []string
	}{
		{
			name: "hping3", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return hping.New(g, a, e, o...)
			},
			target: "192.0.2.10", args: []string{"-S"},
			want: []string{"hping3", "-S", "--count", "4", "--interval", "u250000", "192.0.2.10"},
		},
		{
			name: "tshark", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return tshark.New(g, a, e, o...)
			},
			target: "capture.pcap",
			want:   []string{"tshark", "-r", "capture.pcap", "-T", "json"},
		},
		{
			name: "skipfish", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return skipfish.New(g, a, e, o...)
			},
			target: "https://lab.local",
			want:   []string{"skipfish", "-o", "tool-output/skipfish", "-l", "2", "https://lab.local"},
		},
		{
			name: "sqlmap", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return sqlmap.New(g, a, e, o...)
			},
			target: "https://lab.local/item?id=1", args: []string{"-p", "id"},
			want: []string{"sqlmap", "-u", "https://lab.local/item?id=1", "--batch", "--output-dir", "tool-output/sqlmap", "-p", "id", "--threads", "1", "--delay", "0.5"},
		},
		{
			name: "metasploit", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return metasploit.New(g, a, e, o...)
			},
			target: "192.0.2.10", args: []string{"operator.rc"},
			want: []string{"msfconsole", "-q", "-r", "operator.rc"},
		},
		{
			name: "hashcat", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return hashcat.New(g, a, e, o...)
			},
			target: "hashes.txt", args: []string{"wordlist.txt", "-m", "0"},
			want: []string{"hashcat", "-m", "0", "hashes.txt", "wordlist.txt"},
		},
		{
			name: "aircrack-ng", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return aircrack.New(g, a, e, o...)
			},
			target: "AA:BB:CC:DD:EE:FF", args: []string{"--live"},
			want: []string{"airodump-ng", "--bssid", "AA:BB:CC:DD:EE:FF"},
		},
		{
			name: "set", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return setoolkit.New(g, a, e, o...)
			},
			target: "engagement:lab", args: []string{"operator-campaign.conf"},
			want: []string{"setoolkit", "operator-campaign.conf"},
		},
		{
			name: "kali-utils", factory: func(g authz.Guardrail, a tools.Auditor, e tools.Executor, o ...tools.CommandAdapterOption) tools.Tool {
				return kali.New(g, a, e, o...)
			},
			target: "https://lab.local",
			want:   []string{"whatweb", "https://lab.local"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := authz.Policy{
				Scope:                 authz.NewScope([]string{test.target}, nil),
				AuthorizationAsserted: true,
				Engagement: authz.EngagementAuthorization{
					ID:        "lab",
					Reference: "signed-roe",
					Operator:  "alice",
					Attested:  true,
				},
			}
			auditor := &auditCollector{}
			adapter := test.factory(
				policy,
				auditor,
				discardExecutor{},
				tools.WithAdapterLookPath(func(binary string) (string, error) { return "/usr/bin/" + binary, nil }),
				tools.WithAdapterRuntimeCheck(func() error { return nil }),
				tools.WithAdapterPreflightCheck(func(tools.Request) error { return nil }),
			)
			request := tools.Request{
				Action: authz.Action{Operator: "alice", EngagementID: "lab"},
				Target: test.target,
				Args:   test.args,
				DryRun: true,
			}
			if err := adapter.Preflight(context.Background(), request); err != nil {
				t.Fatalf("Preflight() error = %v", err)
			}
			result, err := adapter.Run(context.Background(), request)
			if err != nil {
				t.Fatalf("Run(dry-run) error = %v", err)
			}
			if !reflect.DeepEqual(result.Command, test.want) {
				t.Fatalf("command = %#v, want %#v", result.Command, test.want)
			}
			if len(auditor.events) != 1 || auditor.events[0].Result != "dry-run" {
				t.Fatalf("audit events = %#v", auditor.events)
			}
			if adapter.Name() == "" || len(adapter.Capabilities()) == 0 {
				t.Fatalf("adapter metadata incomplete: name=%q capabilities=%v", adapter.Name(), adapter.Capabilities())
			}

			if test.name != "tshark" {
				refusingAdapter := test.factory(authz.Policy{}, &auditCollector{}, discardExecutor{})
				if _, err := refusingAdapter.Run(context.Background(), request); err == nil {
					t.Fatal("active/attested adapter succeeded without authorization, scope, or engagement")
				}
			}
		})
	}
}

func TestActiveAdapterRefusesWithoutScope(t *testing.T) {
	adapter := hping.New(
		authz.Policy{AuthorizationAsserted: true},
		&auditCollector{},
		discardExecutor{},
	)
	_, err := adapter.Run(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "192.0.2.10",
		DryRun: true,
	})
	if err == nil {
		t.Fatal("Run() succeeded without scope")
	}
	if got := fmt.Sprint(err); got == "" {
		t.Fatal("Run() returned an empty refusal")
	}
}

func TestTsharkLiveCaptureRefusesWithoutScope(t *testing.T) {
	adapter := tshark.New(authz.Policy{}, &auditCollector{}, discardExecutor{})
	_, err := adapter.Run(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "eth0",
		Args:   []string{"--live"},
		DryRun: true,
	})
	if err == nil {
		t.Fatal("live capture succeeded without authorization or scope")
	}
}
