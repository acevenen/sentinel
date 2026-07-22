package hunt

import "testing"

func gate(in, out []string) *ScopeGate {
	return NewScopeGate(Program{InScope: in, OutOfScope: out})
}

func TestScopeGateInScope(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		out  []string
		host string
		want bool
	}{
		{"exact in scope", []string{"api.example.com"}, nil, "api.example.com", true},
		{"case insensitive", []string{"api.example.com"}, nil, "API.Example.Com", true},
		{"strips port", []string{"api.example.com"}, nil, "api.example.com:443", true},
		{"wildcard subdomain", []string{"*.example.com"}, nil, "api.example.com", true},
		{"wildcard base", []string{"*.example.com"}, nil, "example.com", true},
		{"unlisted host denied (fail closed)", []string{"api.example.com"}, nil, "evil.com", false},
		{"empty host denied", []string{"*.example.com"}, nil, "", false},
		{"out of scope wins over in scope", []string{"*.example.com"}, []string{"admin.example.com"}, "admin.example.com", false},
		{"out of scope wins over exact in", []string{"admin.example.com"}, []string{"admin.example.com"}, "admin.example.com", false},
		{"sibling not matched by exact", []string{"api.example.com"}, nil, "api2.example.com", false},
		{"unrelated domain not matched by wildcard", []string{"*.example.com"}, nil, "example.com.evil.com", false},
		{"no scope at all denies", nil, nil, "anything.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gate(tt.in, tt.out).InScope(tt.host); got != tt.want {
				t.Errorf("InScope(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestHostMatches(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "notexample.com", false},
		{"", "example.com", false},
	}
	for _, tt := range tests {
		if got := hostMatches(tt.pattern, tt.host); got != tt.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}
