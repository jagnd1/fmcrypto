package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type checkerFunc func(context.Context) error

func (f checkerFunc) Ready(ctx context.Context) error { return f(ctx) }

func TestReadinessReflectsProvider(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"ready", nil, http.StatusOK},
		{"unavailable", errors.New("session down"), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			Register(mux, checkerFunc(func(context.Context) error { return tc.err }))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestLivenessDoesNotDependOnProvider(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux, checkerFunc(func(context.Context) error { return errors.New("session down") }))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
