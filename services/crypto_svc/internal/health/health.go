package health

import (
	"log/slog"
	"net/http"

	"common/httpx"
	"common/middleware"
)

// Register mounts the public liveness/readiness probes. The crypto service is
// stateless, so readiness always reflects a healthy process.
func Register(mux *http.ServeMux) {
	mux.Handle("GET /healthz", middleware.RoutePattern("GET /healthz")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}),
	))

	mux.Handle("GET /readyz", middleware.RoutePattern("GET /readyz")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}),
	))

	// Legacy Python-era health probe, kept for drop-in compatibility.
	mux.Handle("GET /health", middleware.RoutePattern("GET /health")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.DebugContext(r.Context(), "health")
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}),
	))
}