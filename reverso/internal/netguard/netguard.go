// Package netguard provides a fail-closed network policy for analysis workers.
// Passive analysis must never open a socket: PCAP and bus captures are read
// from files, firmware is read from disk, and nothing is transmitted. The
// passive dialer refuses every connection so a regression that tries to reach
// the network fails loudly instead of silently emitting traffic.
package netguard

import (
	"context"
	"errors"
	"net"
)

// ErrNetworkDisabled is returned for every dial attempt in passive mode.
var ErrNetworkDisabled = errors.New("network access is disabled in passive analysis mode")

// Dialer matches the net.Dialer surface used by http.Transport and gRPC.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Passive is a Dialer that refuses all connections.
type Passive struct{}

// DialContext always fails closed.
func (Passive) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	return nil, ErrNetworkDisabled
}

// Dial always fails closed.
func (Passive) Dial(network, address string) (net.Conn, error) {
	return nil, ErrNetworkDisabled
}
