package health

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"common/httpx"
	"common/middleware"
)

type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

// Register mounts public liveness and provider-aware readiness probes.
func Register(mux *http.ServeMux, checker ReadinessChecker) {
	mux.Handle("GET /healthz", middleware.RoutePattern("GET /healthz")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}),
	))

	mux.Handle("GET /readyz", middleware.RoutePattern("GET /readyz")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := checker.Ready(ctx); err != nil {
				slog.WarnContext(r.Context(), "hsm not ready", "err", err)
				httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
				return
			}
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}),
	))

	// Legacy health probe, kept for drop-in compatibility.
	mux.Handle("GET /health", middleware.RoutePattern("GET /health")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.DebugContext(r.Context(), "health")
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}),
	))
}
