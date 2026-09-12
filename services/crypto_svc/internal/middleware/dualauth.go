// Package middleware holds transport middleware specific to the crypto
// service. Common middleware lives in common/middleware.
package middleware

import (
	"net/http"
	"strings"

	"common/auth"
	"common/errs"
	"common/respond"
)

// DualAuth authenticates REST callers with either a bearer JWT (validated via
// the injected Authenticator) or an API key (via the injected APIKeyVerifier).
// The API key may be presented as `X-API-Key: <key>` or
// `Authorization: Bearer <key>` (distinguished by the configured prefix).
// The UserContext is stored in the request context; per-route RBAC is enforced
// downstream by the Authorizer.
func DualAuth(a auth.Authenticator, k auth.APIKeyVerifier, prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")

			if strings.HasPrefix(raw, "Bearer ") {
				token := strings.TrimPrefix(raw, "Bearer ")
				if strings.HasPrefix(token, prefix) {
					uc, err := k.ValidateAPIKey(r.Context(), token)
					if err != nil {
						respond.Err(w, r, errs.UnAuth{Msg: "invalid api key"})
						return
					}
					next.ServeHTTP(w, r.WithContext(auth.WithUserContext(r.Context(), uc)))
					return
				}
				uc, err := a.Validate(r.Context(), token)
				if err != nil {
					respond.Err(w, r, errs.UnAuth{Msg: "invalid token"})
					return
				}
				next.ServeHTTP(w, r.WithContext(auth.WithUserContext(r.Context(), uc)))
				return
			}

			if key := r.Header.Get("X-API-Key"); key != "" {
				uc, err := k.ValidateAPIKey(r.Context(), key)
				if err != nil {
					respond.Err(w, r, errs.UnAuth{Msg: "invalid api key"})
					return
				}
				next.ServeHTTP(w, r.WithContext(auth.WithUserContext(r.Context(), uc)))
				return
			}

			respond.Err(w, r, errs.UnAuth{Msg: "authentication required"})
		})
	}
}