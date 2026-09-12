package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"common/auth"
)

type fakeAuthenticator struct {
	uc  auth.UserContext
	err error
}

func (f fakeAuthenticator) Validate(ctx context.Context, token string) (auth.UserContext, error) {
	return f.uc, f.err
}

func TestAuthValid(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uc, found := auth.UserFromContext(r.Context())
		if !found || uc.Subject != "s1" || uc.Roles[0] != "admin" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := Auth(fakeAuthenticator{uc: auth.UserContext{Subject: "s1", Roles: []string{"admin"}}})(ok)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestAuthMissingHeader(t *testing.T) {
	h := Auth(fakeAuthenticator{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestAuthInvalidToken(t *testing.T) {
	h := Auth(fakeAuthenticator{err: io.ErrUnexpectedEOF})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
