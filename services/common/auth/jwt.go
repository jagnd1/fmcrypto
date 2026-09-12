package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var errInvalidToken = errors.New("invalid token")

func tokenKid(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errInvalidToken
	}
	hdrB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errInvalidToken
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		return "", errInvalidToken
	}
	if hdr.Kid == "" {
		return "", errInvalidToken
	}
	return hdr.Kid, nil
}

func parseAndVerify(token string, pub *rsa.PublicKey, cfg VerifierConfig) (map[string]any, error) {
	if len(token) == 0 || len(token) > 16<<10 {
		return nil, errInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}
	hdrB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errInvalidToken
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		return nil, errInvalidToken
	}
	if hdr.Alg != "RS256" { // before any crypto: kills alg-confusion / "none"
		return nil, errInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errInvalidToken
	}
	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadB, &claims); err != nil {
		return nil, errInvalidToken
	}
	if err := validateClaims(claims, cfg); err != nil {
		return nil, err
	}
	return claims, nil
}

func validateClaims(claims map[string]any, cfg VerifierConfig) error {
	now := time.Now().Unix()
	const leeway = 30

	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	exp, _ := claims["exp"].(float64)
	nbf, _ := claims["nbf"].(float64)

	if sub == "" {
		return errInvalidToken
	}
	if exp == 0 || now > int64(exp)+leeway { // exp is required, not optional
		return errInvalidToken
	}
	if nbf != 0 && now < int64(nbf)-leeway {
		return errInvalidToken
	}
	if iss != cfg.Issuer {
		return errInvalidToken
	}
	if !audContains(claims["aud"], cfg.Audience) {
		return errInvalidToken
	}
	return nil
}

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
