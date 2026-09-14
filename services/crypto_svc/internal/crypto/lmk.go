package crypto

import (
	"crypto/des"
	"fmt"
)

// Software-HSM symmetric key layer. Keys are held "under the LMK" as TR-31
// (version D) key blocks. The LMK is derived from the configured master
// secret. GP uses sha256("lmk") only as a deterministic local/test fallback;
// configuration prevents the GP provider from running in production.

const (
	headerSym    = "DD0AB00E" // AES
	headerSymTDE = "DP0TE00N" // TDES
	headerIpek   = "DB1AX00E"
	headerAsym   = "DS0ES00E"
)

// Lmk returns the software-HSM local master key (AES-256).
func Lmk(masterSecret []byte) []byte {
	if len(masterSecret) == 0 {
		masterSecret = []byte("lmk")
	}
	return sha256Sum(masterSecret)
}

// headerFor returns the TR-31 compact header for a symmetric algo.
func headerFor(algo Algo) string {
	if algo == AlgoTDES {
		return headerSymTDE
	}
	return headerSym
}

// WrapKey wraps a clear key under the LMK into a TR-31 block string.
func WrapKey(algo Algo, lmk, key []byte, header string) (string, error) {
	if header == "" {
		header = headerFor(algo)
	}
	return tr31Wrap(lmk, key, header, 0)
}

// UnwrapKey extracts the clear key from a TR-31 block string under the LMK.
func UnwrapKey(algo Algo, lmk []byte, blob string) ([]byte, error) {
	return tr31Unwrap(lmk, blob)
}

// GenKey generates a random symmetric key and wraps it under the LMK.
func GenKey(algo Algo, lmk []byte) (string, error) {
	keyLen, err := algo.keyLenBytes()
	if err != nil {
		return "", err
	}
	key, err := randomBytes(keyLen)
	if err != nil {
		return "", err
	}
	return WrapKey(algo, lmk, key, "")
}

// blockSize returns the cipher block size for the algo (8 TDES, 16 AES).
func blockSize(algo Algo) int {
	if algo == AlgoTDES {
		return des.BlockSize
	}
	return 16
}

// Encrypt unwraps the key and encrypts data (PKCS7 padded) in the given mode.
func Encrypt(algo Algo, lmk []byte, mode EncrMode, keyBlob string, iv, data []byte) ([]byte, error) {
	key, err := UnwrapKey(algo, lmk, keyBlob)
	if err != nil {
		return nil, err
	}
	bs := blockSize(algo)
	padded, err := pkcs7Pad(data, bs)
	if err != nil {
		return nil, err
	}
	return blockEncrypt(algo, mode, key, iv, padded)
}

// Decrypt unwraps the key and decrypts data. PKCS7-unpadding is applied only
// when the plaintext is not exactly one block long.
func Decrypt(algo Algo, lmk []byte, mode EncrMode, keyBlob string, iv, data []byte) ([]byte, error) {
	key, err := UnwrapKey(algo, lmk, keyBlob)
	if err != nil {
		return nil, err
	}
	dec, err := blockDecrypt(algo, mode, key, iv, data)
	if err != nil {
		return nil, err
	}
	bs := blockSize(algo)
	if len(dec) != bs {
		return pkcs7Unpad(dec, bs)
	}
	return dec, nil
}

// Sign computes the AES-CMAC of data using the unwrapped key.
func Sign(algo Algo, lmk []byte, keyBlob string, data []byte) ([]byte, error) {
	key, err := UnwrapKey(algo, lmk, keyBlob)
	if err != nil {
		return nil, err
	}
	return aesCMAC(key, data)
}

// GetKCV returns the key check value: first 3 bytes of AES-CMAC over 16 zero
// bytes (AES algos only).
func GetKCV(algo Algo, lmk []byte, keyBlob string) ([]byte, error) {
	if algo == AlgoTDES {
		return []byte{}, nil
	}
	mac, err := Sign(algo, lmk, keyBlob, make([]byte, 16))
	if err != nil {
		return nil, err
	}
	return mac[:3], nil
}

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	return randomBytes(n)
}

func blockEncrypt(algo Algo, mode EncrMode, key, iv, data []byte) ([]byte, error) {
	switch mode {
	case EncrModeECB:
		return ecbEncrypt(algo, key, data)
	case EncrModeCBC, EncrModeCBCPad:
		return cbcEncrypt(algo, key, iv, data)
	case EncrModeGCM:
		return gcmEncrypt(algo, key, iv, data)
	}
	return nil, fmt.Errorf("%w: unsupported encr mode %q", ErrInvalid{}, mode)
}

func blockDecrypt(algo Algo, mode EncrMode, key, iv, data []byte) ([]byte, error) {
	switch mode {
	case EncrModeECB:
		return ecbDecrypt(algo, key, data)
	case EncrModeCBC, EncrModeCBCPad:
		return cbcDecrypt(algo, key, iv, data)
	case EncrModeGCM:
		return gcmDecrypt(algo, key, iv, data)
	}
	return nil, fmt.Errorf("%w: unsupported encr mode %q", ErrInvalid{}, mode)
}

func cbcEncrypt(algo Algo, key, iv, data []byte) ([]byte, error) {
	if algo == AlgoTDES {
		return tdesCBCEncrypt(key, iv, data)
	}
	return aesCBCEncrypt(key, iv, data)
}

func cbcDecrypt(algo Algo, key, iv, data []byte) ([]byte, error) {
	if algo == AlgoTDES {
		return tdesCBCDecrypt(key, iv, data)
	}
	return aesCBCDecrypt(key, iv, data)
}

func ecbEncrypt(algo Algo, key, data []byte) ([]byte, error) {
	if algo == AlgoTDES {
		return tdesECBEncrypt(key, data)
	}
	block, err := newAESBlock(key)
	if err != nil {
		return nil, err
	}
	return ecbTransform(block, data, true)
}

func ecbDecrypt(algo Algo, key, data []byte) ([]byte, error) {
	if algo == AlgoTDES {
		return tdesECBDecrypt(key, data)
	}
	block, err := newAESBlock(key)
	if err != nil {
		return nil, err
	}
	return ecbTransform(block, data, false)
}

func gcmEncrypt(algo Algo, key, iv, data []byte) ([]byte, error) {
	if algo == AlgoTDES {
		return nil, ErrInvalid{Msg: "gcm not supported for tdes"}
	}
	out, _, err := aesGCMSeal(key, iv, data)
	return out, err
}

func gcmDecrypt(algo Algo, key, iv, data []byte) ([]byte, error) {
	if algo == AlgoTDES {
		return nil, ErrInvalid{Msg: "gcm not supported for tdes"}
	}
	return aesGCMOpen(key, iv, data)
}
