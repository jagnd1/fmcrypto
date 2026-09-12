// Package auth defines the authentication seam for the crypto service.
// The service authenticates machine clients with API keys (no IdP); the
// UserContext flows through the request context for RBAC.
package auth

import "context"

// UserContext carries the authenticated principal through the request context.
type UserContext struct {
	Subject string
	OrgID   string
	Roles   []string
}

// APIKeyVerifier validates opaque API keys (machine clients). Implemented by
// the service's stateless key store.
type APIKeyVerifier interface {
	ValidateAPIKey(ctx context.Context, key string) (UserContext, error)
}

type userCtxKey struct{}

func WithUserContext(ctx context.Context, uc UserContext) context.Context {
	return context.WithValue(ctx, userCtxKey{}, uc)
}

func UserFromContext(ctx context.Context) (UserContext, bool) {
	uc, ok := ctx.Value(userCtxKey{}).(UserContext)
	return uc, ok
}