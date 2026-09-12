package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// IntrospectionConfig identifies the client used to call Zitadel's OAuth2
// introspection endpoint (for opaque access tokens).
type IntrospectionConfig struct {
	Issuer       string
	Audience     string
	ClientID     string
	ClientSecret string
}

type introspectionVerifier struct {
	cfg    IntrospectionConfig
	httpc  *http.Client
	mapper ClaimMapper
}

// NewIntrospectionVerifier builds an Authenticator for OPAQUE access tokens:
// it POSTs the token to <issuer>/oauth/v2/introspect and maps the returned
// claims via the ClaimMapper. This is the correct resource-server pattern for
// IdPs that issue opaque tokens (this Zitadel version does for jwt-bearer).
func NewIntrospectionVerifier(ctx context.Context, cfg IntrospectionConfig, mapper ClaimMapper, httpc *http.Client) (Authenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || mapper == nil || httpc == nil || httpc.Timeout <= 0 {
		return nil, errors.New("issuer, audience, client credentials, mapper, and a bounded http client are required")
	}
	return &introspectionVerifier{cfg: cfg, httpc: httpc, mapper: mapper}, nil
}

func (v *introspectionVerifier) Validate(ctx context.Context, token string) (UserContext, error) {
	u := strings.TrimSuffix(v.cfg.Issuer, "/") + "/oauth/v2/introspect"
	form := url.Values{}
	form.Set("client_id", v.cfg.ClientID)
	form.Set("client_secret", v.cfg.ClientSecret)
	form.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return UserContext{}, errInvalidToken
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpc.Do(req)
	if err != nil {
		return UserContext{}, errInvalidToken
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return UserContext{}, errInvalidToken
	}

	var claims map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return UserContext{}, errInvalidToken
	}
	active, _ := claims["active"].(bool)
	if !active {
		return UserContext{}, errInvalidToken
	}
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return UserContext{}, errInvalidToken
	}
	if !audContains(claims["aud"], v.cfg.Audience) {
		return UserContext{}, errInvalidToken
	}
	return v.mapper.Map(claims)
}
