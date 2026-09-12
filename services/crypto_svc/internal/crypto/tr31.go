package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// TR-31 (ANSI X9.143) key block, version D (AES). Version D covers every
// key-block header the service uses (DD0AB00E, DP0TE00N, DS0ES00E, DB1AX00E).

const (
	tr31VersionD = "D"
	tr31MACLen   = 16 // AES MAC length in bytes for version D
)

// tr31KeyBlockLen computes the full ASCII key-block length for version D.
// maskedKeyLen is the (possibly masked) key length in bytes.
func tr31KeyBlockLen(maskedKeyLen int) int {
	padLen := 16 - (2+maskedKeyLen)%16
	return 16 + 4 + maskedKeyLen*2 + padLen*2 + tr31MACLen*2
}

// tr31BuildHeader assembles the 16-char TR-31 header (no optional blocks) for
// version D. compact header is an 8-char header: version, usage[2], algorithm,
// mode, versionNum[2], exportability.
func tr31BuildHeader(compact string, maskedKeyLen int) (string, error) {
	if len(compact) != 8 {
		return "", ErrInvalid{Msg: "tr31: header must be 8 chars"}
	}
	v := compact[0:1]
	if v != tr31VersionD {
		return "", ErrInvalid{Msg: "tr31: only version D supported"}
	}
	kbLen := tr31KeyBlockLen(maskedKeyLen)
	if kbLen > 9999 {
		return "", ErrInvalid{Msg: "tr31: key block length exceeds limit"}
	}
	return v + fmt.Sprintf("%04d", kbLen) + compact[1:] + "0000", nil
}

// tr31KDF derives the KBEK/KBAK for version D from the KBPK (AES).
func tr31KDF(kbpk []byte) (kbek, kbak []byte, err error) {
	switch len(kbpk) {
	case 16, 24, 32:
	default:
		return nil, nil, ErrInvalid{Msg: "tr31: kbpk must be aes-128/192/256"}
	}
	kdInput := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	calls := []byte{1}
	switch len(kbpk) {
	case 24:
		kdInput[4], kdInput[5] = 0x00, 0x03
		kdInput[6], kdInput[7] = 0x00, 0xC0
		calls = []byte{1, 2}
	case 32:
		kdInput[4], kdInput[5] = 0x00, 0x04
		kdInput[6], kdInput[7] = 0x01, 0x00
		calls = []byte{1, 2}
	}

	_, k2, err := cmacSubkeys(kbpk)
	if err != nil {
		return nil, nil, err
	}

	var (
		ek, ak []byte
		buf    = make([]byte, len(kdInput))
	)
	for _, c := range calls {
		kdInput[0] = c
		// encryption key
		copy(buf, kdInput)
		buf[1], buf[2] = 0x00, 0x00
		m, err := aesCBCMAC(kbpk, xor(buf, k2))
		if err != nil {
			return nil, nil, err
		}
		ek = append(ek, m...)
		// authentication key
		copy(buf, kdInput)
		buf[1], buf[2] = 0x00, 0x01
		m, err = aesCBCMAC(kbpk, xor(buf, k2))
		if err != nil {
			return nil, nil, err
		}
		ak = append(ak, m...)
	}
	return ek[:len(kbpk)], ak[:len(kbpk)], nil
}

// tr31GenerateMAC computes the key-block MAC over header||clearKeyData.
func tr31GenerateMAC(kbak, header, clearKeyData []byte) ([]byte, error) {
	km1, _, err := cmacSubkeys(kbak)
	if err != nil {
		return nil, err
	}
	// XOR the last 16 bytes with K1, then CBC-MAC.
	n := len(clearKeyData)
	macData := make([]byte, len(header)+n)
	copy(macData, header)
	copy(macData[len(header):], clearKeyData)
	last := len(macData) - 16
	copy(macData[last:], xor(macData[last:], km1))
	return aesCBCMAC(kbak, macData)
}

// tr31Wrap encrypts key under kbpk into a TR-31 version D key block string.
// compact is the 8-char header; maskedKeyLen is the masked key length in bytes
// (0 = use the actual key length).
func tr31Wrap(kbpk, key []byte, compact string, maskedKeyLen int) (string, error) {
	if maskedKeyLen < len(key) {
		maskedKeyLen = len(key)
	}
	header, err := tr31BuildHeader(compact, maskedKeyLen)
	if err != nil {
		return "", err
	}
	kbek, kbak, err := tr31KDF(kbpk)
	if err != nil {
		return "", err
	}

	// clear key data: 2-byte bit length + key + random pad
	padLen := 16 - (2+maskedKeyLen)%16
	extraPad := maskedKeyLen - len(key)
	clearKeyData := make([]byte, 2+maskedKeyLen+padLen)
	clearKeyData[0] = byte(len(key) * 8 >> 8)
	clearKeyData[1] = byte(len(key) * 8)
	copy(clearKeyData[2:], key)
	pad, err := randomBytes(padLen + extraPad)
	if err != nil {
		return "", err
	}
	copy(clearKeyData[2+len(key):], pad)

	mac, err := tr31GenerateMAC(kbak, []byte(header), clearKeyData)
	if err != nil {
		return "", err
	}
	enc, err := aesCBCEncrypt(kbek, mac, clearKeyData)
	if err != nil {
		return "", err
	}
	return header + strings.ToUpper(hex.EncodeToString(enc)) + strings.ToUpper(hex.EncodeToString(mac)), nil
}

// tr31Unwrap decrypts a TR-31 version D key block string and returns the key.
func tr31Unwrap(kbpk []byte, block string) ([]byte, error) {
	block = strings.TrimSpace(block)
	if len(block) < 16 {
		return nil, ErrInvalid{Msg: "tr31: key block too short"}
	}
	if block[0] != tr31VersionD[0] {
		return nil, ErrInvalid{Msg: "tr31: only version D supported"}
	}
	kbLen := 0
	if _, err := fmt.Sscanf(block[1:5], "%04d", &kbLen); err != nil || kbLen != len(block) {
		return nil, ErrInvalid{Msg: "tr31: block length mismatch"}
	}
	if len(block)%16 != 0 {
		return nil, ErrInvalid{Msg: "tr31: block length must be multiple of 16"}
	}

	// header = 16-char; MAC = last 32 hex chars; encrypted data = middle.
	header := block[:16]
	receivedMAC, err := hexDecode(block[len(block)-32:])
	if err != nil {
		return nil, err
	}
	keyData, err := hexDecode(block[16 : len(block)-32])
	if err != nil {
		return nil, err
	}
	if len(keyData) < 16 || len(keyData)%16 != 0 {
		return nil, ErrInvalid{Msg: "tr31: encrypted key data malformed"}
	}

	kbek, kbak, err := tr31KDF(kbpk)
	if err != nil {
		return nil, err
	}
	clearKeyData, err := aesCBCDecrypt(kbek, receivedMAC, keyData)
	if err != nil {
		return nil, err
	}
	mac, err := tr31GenerateMAC(kbak, []byte(header), clearKeyData)
	if err != nil {
		return nil, err
	}
	if !equalBytes(mac, receivedMAC) {
		return nil, ErrInvalid{Msg: "tr31: mac mismatch"}
	}

	keyLen := int(clearKeyData[0])<<8 | int(clearKeyData[1])
	if keyLen%8 != 0 {
		return nil, ErrInvalid{Msg: "tr31: key length not whole bytes"}
	}
	keyLen /= 8
	if keyLen < 0 || keyLen+2 > len(clearKeyData) {
		return nil, ErrInvalid{Msg: "tr31: key length out of range"}
	}
	return clearKeyData[2 : 2+keyLen], nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}