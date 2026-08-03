// Command reverso is an authorization-first agent for defensive reverse
// engineering of owner-controlled and laboratory hardware. It is observation-
// first and fails closed: without a signed, unexpired authorization manifest it
// refuses to analyze anything, and it will never operationalize keys, bypass
// secure boot, defeat gateway authentication, or emit to a real vehicle bus.
//
// Exit codes: 0 = success, 1 = a command reported a policy/verification failure,
// 2 = a tool or usage error.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/acevenen/sentinel/reverso/internal/cli"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := cli.NewRootCmd().ExecuteContext(ctx)
	switch {
	case err == nil:
		return
	case isPolicyRefusal(err):
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

// isPolicyRefusal maps authorization refusals to exit code 1 so scripts can
// distinguish a deliberate, safe refusal from a tool error.
func isPolicyRefusal(err error) bool {
	for _, target := range []error{
		scope.ErrNoAuthorization,
		scope.ErrScopeExpired,
		scope.ErrUnverified,
		scope.ErrPermanentlyProhibited,
		scope.ErrProhibitedByManifest,
		scope.ErrNotPermitted,
		scope.ErrAssetTypeMismatch,
		scope.ErrApprovalRequired,
		scope.ErrLabOnlyRequired,
		scope.ErrSimulatorRequired,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
