package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"common/respond"
)

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.ErrorContext(r.Context(), "panic",
					"err", err,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				respond.Internal(w, r)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
