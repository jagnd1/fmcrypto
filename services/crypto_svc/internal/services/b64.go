package services

import (
	"encoding/base64"
	"fmt"
	"strings"

	"cryptosvc/internal/crypto"
)

// Base64url helpers (padded), tolerant of missing padding on decode (the
// Android NO_PADDING fix).

func b64Encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	s = strings.TrimSpace(s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, crypto.ErrInvalid{Msg: fmt.Sprintf("invalid base64 value: %v", err)}
	}
	return b, nil
}
