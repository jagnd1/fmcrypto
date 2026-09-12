package auth

import (
	"context"
)

type UserContext struct {
	Subject string
	OrgID   string
	Roles   []string
}

// Authenticator is the transport-level seam: any IdP verifier (Zitadel, Okta,
// Keycloak) implements it. common/middleware.Auth depends only on this.
type Authenticator interface {
	Validate(ctx context.Context, token string) (UserContext, error)
}

// APIKeyVerifier validates opaque API keys (machine clients). The interface
// lives here (shared seam); the implementation is service-specific (DB-backed).
type APIKeyVerifier interface {
	ValidateAPIKey(ctx context.Context, key string) (UserContext, error)
}

// ClaimMapper is the provider seam: only the claim → UserContext shape differs
// per IdP (roles/org). The generic OIDC verifier handles everything else.
type ClaimMapper interface {
	Map(claims map[string]any) (UserContext, error)
}

type VerifierConfig struct {
	Issuer   string
	Audience string
}

type userCtxKey struct{}

func WithUserContext(ctx context.Context, uc UserContext) context.Context {
	return context.WithValue(ctx, userCtxKey{}, uc)
}

func UserFromContext(ctx context.Context) (UserContext, bool) {
	uc, ok := ctx.Value(userCtxKey{}).(UserContext)
	return uc, ok
}
