package netguard

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestPassiveDialerRefuses(t *testing.T) {
	if _, err := (Passive{}).DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrNetworkDisabled) {
		t.Fatalf("DialContext error = %v, want ErrNetworkDisabled", err)
	}
	if _, err := (Passive{}).Dial("tcp", "10.0.0.1:80"); !errors.Is(err, ErrNetworkDisabled) {
		t.Fatalf("Dial error = %v, want ErrNetworkDisabled", err)
	}
}

// An HTTP client wired with the passive dialer must never reach the network,
// proving passive mode cannot transmit even through a standard transport.
func TestPassiveDialerBlocksHTTPClient(t *testing.T) {
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DialContext: Passive{}.DialContext},
	}
	_, err := client.Get("http://192.0.2.1/") // TEST-NET-1, never routable
	if err == nil {
		t.Fatal("passive-mode HTTP client made a request; it must fail closed")
	}
}
