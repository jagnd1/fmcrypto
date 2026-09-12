package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hkdfSHA256 implements RFC 5869 HKDF with HMAC-SHA256 using only the stdlib.
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// extract
	prk := hmacSHA256(salt, secret)
	// expand
	var (
		out     []byte
		t       []byte
		counter byte = 1
	)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// x963KDFContext is the fixed HKDF info string defined by the X9.63 ECDH
// key-derivation convention.
var x963KDFContext = []byte("ANSI X9.63 KDF Context")

// ecdhHKDF derives the X9.63 session key from an ECDH shared secret.
func ecdhHKDF(sharedSecret []byte, keyLen int) []byte {
	return hkdfSHA256(sharedSecret, nil, x963KDFContext, keyLen)
}
