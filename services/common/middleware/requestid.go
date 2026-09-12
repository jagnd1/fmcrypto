package middleware

import (
	"log/slog"
	"net/http"
	"regexp"

	"common/ids"
	"common/reqctx"
	"common/respond"
)

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if len(id) > 64 || !requestIDRE.MatchString(id) {
			var err error
			id, err = ids.New()
			if err != nil {
				slog.ErrorContext(r.Context(), "generate request id", "err", err)
				respond.Internal(w, r)
				return
			}
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(reqctx.WithRequestID(r.Context(), id)))
	})
}
