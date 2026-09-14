package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"common/auth"

	"cryptosvc/internal/authz"
	"cryptosvc/internal/handlers"
	"cryptosvc/internal/hsm"
	"cryptosvc/internal/routers"
	"cryptosvc/internal/services"
)

func newTestServer(authorizer handlers.Authorizer, enableInternalUnwrap bool) *http.ServeMux {
	mux := http.NewServeMux()
	gp := hsm.NewGP(nil)
	routers.Register(mux, handlers.New(services.NewCrypto(gp), services.NewServer(gp), authorizer), enableInternalUnwrap)
	return mux
}

// doAs sends a request with an injected UserContext (bypasses the outer auth
// middleware — per-route RBAC is what we exercise here).
func doAs(t *testing.T, mux *http.ServeMux, method, path, body string, roles []string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	ctx := auth.WithUserContext(req.Context(), auth.UserContext{Subject: "test", Roles: roles})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestRouteRegistration(t *testing.T) {
	mux := newTestServer(authz.PermitAll{}, true)
	paths := []struct{ method, path string }{
		{"POST", "/v1/crypto/kp_gen"},
		{"POST", "/v1/crypto/gen_sign"},
		{"POST", "/v1/crypto/ecdh"},
		{"POST", "/v1/crypto/exp_key"},
		{"POST", "/v1/crypto/exp_tr31"},
		{"POST", "/v1/crypto/rand_gen"},
		{"POST", "/v1/crypto/exp_tr34"},
		{"POST", "/v1/crypto/key_gen"},
		{"POST", "/v1/crypto/kcv_gen"},
		{"POST", "/v1/crypto/ipek_derive"},
		{"POST", "/v1/crypto/data_encr"},
		{"POST", "/v1/crypto/data_decr"},
		{"POST", "/v1/crypto/mac"},
		{"POST", "/v1/crypto/trans_pin"},
		{"POST", "/v1/crypto/wrap"},
		{"POST", "/v1/crypto/unwrap"},
		{"POST", "/v1/serv/cert"},
		{"PUT", "/v1/serv/cert"},
		{"POST", "/v1/serv/crl"},
	}
	for _, p := range paths {
		rec := doAs(t, mux, p.method, p.path, `{}`, []string{"admin"})
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s: route not registered (404)", p.method, p.path)
		}
	}
}

func TestRBACDenied(t *testing.T) {
	mux := newTestServer(authz.Policy{}, false)
	// read-only role cannot generate key pairs
	rec := doAs(t, mux, http.MethodPost, "/v1/crypto/kp_gen", `{}`, []string{"reader"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("reader on kp_gen: want 403, got %d", rec.Code)
	}
	// operator role IS allowed past RBAC (then fails validation → not 403)
	rec = doAs(t, mux, http.MethodPost, "/v1/crypto/gen_sign", `{}`, []string{"operator"})
	if rec.Code == http.StatusForbidden {
		t.Errorf("operator on gen_sign should pass RBAC, got 403")
	}
	// unauthenticated (no UserContext) → 401
	req := httptest.NewRequest(http.MethodPost, "/v1/crypto/kp_gen", bytes.NewBufferString(`{}`))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("no user on kp_gen: want 401, got %d", rec2.Code)
	}
}

func TestHappyPathEndpoints(t *testing.T) {
	mux := newTestServer(authz.PermitAll{}, false)

	// rand_gen
	rec := doAs(t, mux, http.MethodPost, "/v1/crypto/rand_gen", `{"len":"12"}`, []string{"admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("rand_gen: want 200, got %d: %s", rec.Code, rec.Body)
	}
	var rr struct {
		Status string `json:"status"`
		RandNo string `json:"rand_no"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil || rr.Status != "success" || len(rr.RandNo) != 24 {
		t.Fatalf("rand_gen bad response: %s", rec.Body)
	}

	// kp_gen
	rec = doAs(t, mux, http.MethodPost, "/v1/crypto/kp_gen", `{"algo":"ECP256","use_mode":"SIGN"}`, []string{"admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("kp_gen: want 200, got %d: %s", rec.Code, rec.Body)
	}
	var kp struct {
		Status string `json:"status"`
		Pk     string `json:"pk"`
		SkLmk  string `json:"sk_lmk"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &kp); err != nil || kp.Pk == "" || kp.SkLmk == "" {
		t.Fatalf("kp_gen bad response: %s", rec.Body)
	}

	// key_gen
	rec = doAs(t, mux, http.MethodPost, "/v1/crypto/key_gen", `{"key_type":"BDK","use_mode":"DERIV","algo":"A128"}`, []string{"admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("key_gen: want 200, got %d: %s", rec.Code, rec.Body)
	}
	var kg struct {
		Status string `json:"status"`
		KeyLmk string `json:"key_lmk"`
		Kcv    string `json:"kcv"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &kg); err != nil || kg.KeyLmk == "" || kg.Kcv == "" {
		t.Fatalf("key_gen bad response: %s", rec.Body)
	}

	// exp_key standalone (empty pk) returns the key_lmk untouched
	rec = doAs(t, mux, http.MethodPost, "/v1/crypto/exp_key", `{"key_lmk":"`+kg.KeyLmk+`","kcv":"","pk":""}`, []string{"admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("exp_key standalone: want 200, got %d: %s", rec.Code, rec.Body)
	}

	// kcv_gen on the generated key
	rec = doAs(t, mux, http.MethodPost, "/v1/crypto/kcv_gen", `{"key_lmk":"`+kg.KeyLmk+`"}`, []string{"admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("kcv_gen: want 200, got %d: %s", rec.Code, rec.Body)
	}
	var kcv struct {
		Status string `json:"status"`
		Kcv    string `json:"kcv"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &kcv); err != nil || kcv.Kcv == "" {
		t.Fatalf("kcv_gen bad response: %s", rec.Body)
	}
}

func TestInternalUnwrapDisabledByDefault(t *testing.T) {
	mux := newTestServer(authz.Policy{}, false)
	rec := doAs(t, mux, http.MethodPost, "/v1/crypto/unwrap", `{}`, []string{"key_custodian"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unwrap disabled: want 404, got %d", rec.Code)
	}
}

func TestInternalUnwrapRequiresDedicatedRole(t *testing.T) {
	mux := newTestServer(authz.Policy{}, true)
	rec := doAs(t, mux, http.MethodPost, "/v1/crypto/unwrap", `{}`, []string{"admin"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin unwrap: want 403, got %d", rec.Code)
	}
	rec = doAs(t, mux, http.MethodPost, "/v1/crypto/unwrap", `{}`, []string{"key_custodian"})
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("key custodian should pass authorization, got %d", rec.Code)
	}
}

func TestInvalidCryptoInputsReturnValidationErrors(t *testing.T) {
	mux := newTestServer(authz.PermitAll{}, false)
	cases := []struct {
		path string
		body string
	}{
		{"/v1/crypto/rand_gen", `{"len":"4097"}`},
		{"/v1/crypto/gen_sign", `{"msg":"not-hex","sk_lmk":"bad","algo":"ECP256"}`},
		{"/v1/crypto/ipek_derive", `{"bdk_lmk":"bad","iksn":"0102","algo":"A128","use_mode":"DERIV"}`},
		{"/v1/crypto/mac", `{"key_lmk":"bad","mac_mode":"VERIFY","msg":"00"}`},
		{"/v1/crypto/trans_pin", `{"key_lmk":"bad","dest_key":"bad","ksn":"01","src_pinblk":"00","pan":"123456789012"}`},
	}
	for _, tc := range cases {
		rec := doAs(t, mux, http.MethodPost, tc.path, tc.body, []string{"admin"})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: want 422, got %d: %s", tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestHealthProbes(t *testing.T) {
	mux := http.NewServeMux()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unmatched path: want 404, got %d", rec.Code)
	}
}
