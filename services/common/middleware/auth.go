package middleware

import (
	"net/http"
	"strings"

	"common/auth"
	"common/errs"
	"common/respond"
)

// Auth validates the bearer token via the injected Authenticator and stores the
// UserContext in the request context. Transport-generic — never knows the IdP.
func Auth(a auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			if !strings.HasPrefix(raw, "Bearer ") {
				respond.Err(w, r, errs.UnAuth{Msg: "authentication required"})
				return
			}
			uc, err := a.Validate(r.Context(), strings.TrimPrefix(raw, "Bearer "))
			if err != nil {
				respond.Err(w, r, errs.UnAuth{Msg: "invalid token"})
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUserContext(r.Context(), uc)))
		})
	}
}
