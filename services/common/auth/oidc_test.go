package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mintToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, aud string, exp time.Time, extra map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	payload := map[string]any{
		"sub": "u1", "iss": issuer, "aud": aud,
		"exp": exp.Unix(), "iat": time.Now().Unix(),
	}
	for k, v := range extra {
		payload[k] = v
	}
	hdr := enc(map[string]any{"alg": "RS256", "kid": kid})
	p := enc(payload)
	digest := sha256.Sum256([]byte(hdr + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return hdr + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func fakeOIDC(t *testing.T, key *rsa.PrivateKey, kid string) (issuer string, stop func()) {
	t.Helper()
	var srv *httptest.Server
	issuer = "http://idp.test"
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := &key.PublicKey
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kid": kid, "kty": "RSA", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	srv = httptest.NewServer(mux)
	return srv.URL, srv.Close
}

func rsaKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, "kid-1"
}

func newTestVerifier(t *testing.T, mapper ClaimMapper) (*oidcVerifier, *rsa.PrivateKey, string) {
	t.Helper()
	key, kid := rsaKey(t)
	issuer, stop := fakeOIDC(t, key, kid)
	t.Cleanup(stop)
	v, err := NewOIDCVerifier(context.Background(), VerifierConfig{Issuer: issuer, Audience: "api-client"}, mapper, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return v.(*oidcVerifier), key, kid
}

func TestValidateOK(t *testing.T) {
	v, key, kid := newTestVerifier(t, ZitadelMapper{})
	token := mintToken(t, key, kid, v.cfg.Issuer, v.cfg.Audience, time.Now().Add(time.Hour), map[string]any{
		"urn:zitadel:iam:org:project:roles": map[string]any{"admin": map[string]any{"org1": "org1"}},
	})
	uc, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if uc.Subject != "u1" || uc.OrgID != "org1" {
		t.Fatalf("got %+v", uc)
	}
	if len(uc.Roles) != 1 || uc.Roles[0] != "admin" {
		t.Fatalf("roles = %v", uc.Roles)
	}
}

func TestValidateRejectsWrongAud(t *testing.T) {
	v, key, kid := newTestVerifier(t, ZitadelMapper{})
	token := mintToken(t, key, kid, v.cfg.Issuer, "other-client", time.Now().Add(time.Hour), nil)
	if _, err := v.Validate(context.Background(), token); err == nil {
		t.Fatal("want error for wrong audience")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	v, key, kid := newTestVerifier(t, ZitadelMapper{})
	token := mintToken(t, key, kid, v.cfg.Issuer, v.cfg.Audience, time.Now().Add(-time.Hour), nil)
	if _, err := v.Validate(context.Background(), token); err == nil {
		t.Fatal("want error for expired token")
	}
}

func TestValidateRejectsNoneAlg(t *testing.T) {
	v, key, kid := newTestVerifier(t, ZitadelMapper{})
	// hand-craft a "none"-alg token (header alg=none)
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	hdr := enc(map[string]any{"alg": "none", "kid": kid})
	payload := enc(map[string]any{"sub": "u1", "iss": v.cfg.Issuer, "aud": v.cfg.Audience, "exp": time.Now().Add(time.Hour).Unix()})
	token := hdr + "." + payload + "."
	if _, err := v.Validate(context.Background(), token); err == nil {
		t.Fatal("want error for alg=none")
	}
	_ = key
}

func TestZitadelMapperRejectsAmbiguousOrg(t *testing.T) {
	m := ZitadelMapper{}
	_, err := m.Map(map[string]any{
		"sub": "u1",
		"urn:zitadel:iam:org:project:roles": map[string]any{
			"admin": map[string]any{"org1": "org1"},
			"user":  map[string]any{"org2": "org2"},
		},
	})
	if err == nil {
		t.Fatal("want error for ambiguous org")
	}
}
