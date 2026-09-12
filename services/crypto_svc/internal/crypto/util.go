// Package crypto is the service's crypto provider: pure-Go (stdlib-only)
// key-block (LMK/TR-31), symmetric, asymmetric, and PIN operations with no
// third-party dependencies.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// randomBytes returns n cryptographically secure random bytes.
func randomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalid{Msg: "negative length"}
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ErrInvalid is returned for malformed input/keys.
type ErrInvalid struct{ Msg string }

func (e ErrInvalid) Error() string { return e.Msg }

// xor returns a^b (same length).
func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// shiftLeft1 shifts a byte slice left by one bit (MSB dropped).
func shiftLeft1(in []byte) []byte {
	out := make([]byte, len(in))
	carry := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		next := in[i] >> 7
		out[i] = (in[i] << 1) | carry
		carry = next
	}
	return out
}

// msb reports whether the high bit of the first byte is set.
func msb(in []byte) bool { return in[0]&0x80 != 0 }

// sha256Sum returns SHA-256 digest of data.
func sha256Sum(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}

// hexDecode decodes a hex string, uppercasing tolerance for mixed case.
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%w: odd-length hex", ErrInvalid{})
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return b, nil
}

// pkcs7Pad pads data to blockSize using PKCS#7 (used for AES/TDES block ciphers).
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, ErrInvalid{Msg: "invalid block size"}
	}
	padLen := blockSize - len(data)%blockSize
	if padLen == 0 {
		padLen = blockSize
	}
	pad := byte(padLen)
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = pad
	}
	return out, nil
}

// pkcs7Unpad removes PKCS#7 padding. It tolerates the Python behavior of
// skipping unpadding when the plaintext is already block-aligned.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrInvalid{Msg: "invalid padded data length"}
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, ErrInvalid{Msg: "invalid padding"}
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, ErrInvalid{Msg: "invalid padding bytes"}
		}
	}
	return data[:len(data)-padLen], nil
}