package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// aesCBCEncrypt encrypts data (multiple of 16) under AES-CBC with the given IV.
func aesCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrInvalid{Msg: "aes cbc: data must be a multiple of 16 bytes"}
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrInvalid{Msg: "aes cbc: iv must be 16 bytes"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(data))
	mode.CryptBlocks(out, data)
	return out, nil
}

// aesCBCDecrypt decrypts data (multiple of 16) under AES-CBC with the given IV.
func aesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrInvalid{Msg: "aes cbc: data must be a multiple of 16 bytes"}
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrInvalid{Msg: "aes cbc: iv must be 16 bytes"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(data))
	mode.CryptBlocks(out, data)
	return out, nil
}

// aesECBEncrypt encrypts a single AES block under ECB.
func aesECBEncrypt(key, data []byte) ([]byte, error) {
	if len(data) != aes.BlockSize {
		return nil, ErrInvalid{Msg: "aes ecb: data must be exactly 16 bytes"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, data)
	return out, nil
}

// aesCBCMAC computes the ISO/IEC 9797-1 MAC algorithm 1 (CBC-MAC) over data
// using AES-CBC with a zero IV; returns the last block (16 bytes). Data must be
// a multiple of 16 bytes (callers pad explicitly).
func aesCBCMAC(key, data []byte) ([]byte, error) {
	enc, err := aesCBCEncrypt(key, make([]byte, aes.BlockSize), data)
	if err != nil {
		return nil, err
	}
	return enc[len(enc)-aes.BlockSize:], nil
}

// aesCMAC computes the NIST SP 800-38B AES-CMAC over data.
func aesCMAC(key, data []byte) ([]byte, error) {
	k1, k2, err := cmacSubkeys(key)
	if err != nil {
		return nil, err
	}
	work := append([]byte{}, data...)
	n := len(work) / aes.BlockSize
	last := n * aes.BlockSize
	if len(work) == 0 || len(work)%aes.BlockSize != 0 {
		// partial last block: pad with 0x80 + zeros, XOR last block with K2
		padded := make([]byte, (n+1)*aes.BlockSize)
		copy(padded, work)
		padded[len(work)] = 0x80
		work = padded
		n++
		last = n * aes.BlockSize
		copy(work[last-aes.BlockSize:], xor(work[last-aes.BlockSize:], k2))
	} else {
		// full block: XOR last block with K1
		copy(work[last-aes.BlockSize:], xor(work[last-aes.BlockSize:], k1))
	}
	return aesCBCMAC(key, work)
}

// cmacSubkeys derives the K1/K2 CMAC subkeys from an AES key.
func cmacSubkeys(key []byte) (k1, k2 []byte, err error) {
	zero := make([]byte, aes.BlockSize)
	s, err := aesECBEncrypt(key, zero)
	if err != nil {
		return nil, nil, err
	}
	r := make([]byte, aes.BlockSize)
	r[aes.BlockSize-1] = 0x87
	if msb(s) {
		k1 = xor(shiftLeft1(s), r)
	} else {
		k1 = shiftLeft1(s)
	}
	if msb(k1) {
		k2 = xor(shiftLeft1(k1), r)
	} else {
		k2 = shiftLeft1(k1)
	}
	return k1, k2, nil
}
