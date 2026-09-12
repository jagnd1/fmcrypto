package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type jwksStore struct {
	client *http.Client
	url    string

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastAttempt time.Time
	lastSuccess time.Time
	cacheTTL    time.Duration
}

func newJWKSStore(client *http.Client, jwksURL string) *jwksStore {
	return &jwksStore{
		client:   client,
		url:      jwksURL,
		keys:     map[string]*rsa.PublicKey{},
		cacheTTL: time.Hour,
	}
}

func (s *jwksStore) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	fresh := time.Since(s.lastSuccess) < s.cacheTTL
	s.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	return s.refresh(ctx, kid)
}

func (s *jwksStore) refresh(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[kid]; ok && time.Since(s.lastSuccess) < s.cacheTTL {
		return k, nil
	}
	if time.Since(s.lastAttempt) < 30*time.Second { // bad tokens cannot stampede
		return nil, errInvalidToken
	}
	s.lastAttempt = time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kid, Kty, Alg, Use, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, err
	}

	next := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") ||
			(k.Use != "" && k.Use != "sig") || k.Kid == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
		if pub.N.Sign() <= 0 || pub.N.BitLen() < 2048 || pub.E < 3 || pub.E%2 == 0 {
			continue
		}
		next[k.Kid] = pub
	}
	s.keys = next // replacement removes retired keys
	s.lastSuccess = time.Now()

	k, ok := s.keys[kid]
	if !ok {
		return nil, errInvalidToken
	}
	return k, nil
}
