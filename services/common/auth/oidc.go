package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type oidcVerifier struct {
	cfg    VerifierConfig
	store  *jwksStore
	mapper ClaimMapper
}

// NewOIDCVerifier builds a generic OIDC resource-server verifier. Discovery
// supplies the canonical issuer + jwks_uri (never hand-joined). Any conformant
// IdP works; the ClaimMapper isolates the per-provider role/org claim shape.
func NewOIDCVerifier(ctx context.Context, cfg VerifierConfig, mapper ClaimMapper, client *http.Client) (Authenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || mapper == nil || client == nil || client.Timeout <= 0 {
		return nil, errors.New("issuer, audience, mapper, and a bounded http client are required")
	}
	discoveryURL, err := url.JoinPath(cfg.Issuer, ".well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: unexpected status %d", resp.StatusCode)
	}
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, err
	}
	if d.Issuer != cfg.Issuer || d.JWKSURI == "" {
		return nil, errors.New("oidc discovery did not match configured issuer")
	}
	return &oidcVerifier{
		cfg:    cfg,
		store:  newJWKSStore(client, d.JWKSURI),
		mapper: mapper,
	}, nil
}

func (v *oidcVerifier) Validate(ctx context.Context, token string) (UserContext, error) {
	kid, err := tokenKid(token)
	if err != nil {
		return UserContext{}, errInvalidToken
	}
	pub, err := v.store.key(ctx, kid)
	if err != nil {
		return UserContext{}, errInvalidToken
	}
	claims, err := parseAndVerify(token, pub, v.cfg)
	if err != nil {
		return UserContext{}, errInvalidToken
	}
	return v.mapper.Map(claims)
}
