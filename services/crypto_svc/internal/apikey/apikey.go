package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"common/auth"
	"common/errs"
)

// Verifier validates API keys against a stateless set of sha256 hashes loaded
// from config (env API_KEYS). It implements common/auth.APIKeyVerifier, so the
// same seam powers REST dual-auth and the gRPC interceptor.
type Verifier struct {
	prefix string
	hashes map[string]struct{}
	roles  []string
}

func NewVerifier(prefix string, hashes []string, roles []string) *Verifier {
	set := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		if h != "" {
			set[strings.ToLower(h)] = struct{}{}
		}
	}
	return &Verifier{prefix: prefix, hashes: set, roles: roles}
}

// Hash returns the sha256 hex digest used for storage/comparison.
func Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Generate creates a new API key with the configured prefix. Plaintext is
// returned once; only Hash(plain) is ever persisted.
func (v *Verifier) Generate() (plain string, err error) {
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return "", err
	}
	return v.prefix + hex.EncodeToString(b), nil
}

// ValidateAPIKey implements auth.APIKeyVerifier.
func (v *Verifier) ValidateAPIKey(ctx context.Context, key string) (auth.UserContext, error) {
	if !strings.HasPrefix(key, v.prefix) {
		return auth.UserContext{}, errs.UnAuth{Msg: "invalid api key"}
	}
	if _, ok := v.hashes[Hash(key)]; !ok {
		return auth.UserContext{}, errs.UnAuth{Msg: "invalid api key"}
	}
	return auth.UserContext{Subject: "apikey", Roles: v.roles}, nil
}