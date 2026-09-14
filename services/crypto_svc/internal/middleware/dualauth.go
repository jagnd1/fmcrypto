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

// APIKeyAuth authenticates REST callers with an API key presented either as
// `X-API-Key: <key>` or `Authorization: Bearer <key>`. The UserContext is
// stored in the request context; per-route RBAC is enforced downstream by the
// Authorizer. Wire this only when API keys are configured — otherwise REST is
// open (PermitAll).
func APIKeyAuth(v auth.APIKeyVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				raw := r.Header.Get("Authorization")
				if strings.HasPrefix(raw, "Bearer ") {
					key = strings.TrimPrefix(raw, "Bearer ")
				}
			}
			if key == "" {
				respond.Err(w, r, errs.UnAuth{Msg: "authentication required"})
				return
			}
			uc, err := v.ValidateAPIKey(r.Context(), key)
			if err != nil {
				respond.Err(w, r, errs.UnAuth{Msg: "invalid api key"})
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUserContext(r.Context(), uc)))
		})
	}
}
