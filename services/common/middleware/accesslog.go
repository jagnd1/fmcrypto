package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"common/reqctx"
)

type StatusWriter struct {
	http.ResponseWriter
	Status int
	Bytes  int
}

func (w *StatusWriter) WriteHeader(code int) {
	if w.Status != 0 {
		return
	}
	w.Status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusWriter) Write(b []byte) (int, error) {
	if w.Status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.Bytes += n
	return n, err
}

func (w *StatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *StatusWriter) StatusCode() int {
	if w.Status == 0 {
		return http.StatusOK
	}
	return w.Status
}

func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		meta := &reqctx.AccessMeta{}
		sw := &StatusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(reqctx.WithAccessMeta(r.Context(), meta)))
		route := meta.Route
		if route == "" {
			route = "unmatched"
		}
		slog.InfoContext(r.Context(), "request",
			"method", r.Method,
			"route", route,
			"status", sw.StatusCode(),
			"bytes", sw.Bytes,
			"dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

func RoutePattern(pattern string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if meta, ok := reqctx.AccessMetaFrom(r.Context()); ok {
				meta.Route = pattern
			}
			next.ServeHTTP(w, r)
		})
	}
}
