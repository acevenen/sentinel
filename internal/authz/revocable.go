package authz

import (
	"context"
	"errors"
	"sync/atomic"
)

// Revocable wraps a guardrail with a dynamic fail-closed scope lease. It is
// useful for multi-action workflows whose rules can be withdrawn.
type Revocable struct {
	next    Guardrail
	revoked atomic.Bool
}

// NewRevocable returns a dynamic guardrail around next.
func NewRevocable(next Guardrail) *Revocable {
	return &Revocable{next: next}
}

// Revoke permanently refuses future actions in this process.
func (r *Revocable) Revoke() {
	if r != nil {
		r.revoked.Store(true)
	}
}

// Authorize implements Guardrail.
func (r *Revocable) Authorize(ctx context.Context, action Action) error {
	if r == nil || r.next == nil {
		return errors.New("revocable guardrail has no underlying policy")
	}
	if r.revoked.Load() {
		return ErrScopeRevoked
	}
	return r.next.Authorize(ctx, action)
}
