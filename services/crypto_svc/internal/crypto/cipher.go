package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func newAESBlock(key []byte) (cipher.Block, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return b, nil
}

// ecbTransform applies ECB across all blocks (encrypt or decrypt).
func ecbTransform(block cipher.Block, data []byte, encrypt bool) ([]byte, error) {
	bs := block.BlockSize()
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, ErrInvalid{Msg: "ecb: data must be a multiple of block size"}
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		if encrypt {
			block.Encrypt(out[i:i+bs], data[i:i+bs])
		} else {
			block.Decrypt(out[i:i+bs], data[i:i+bs])
		}
	}
	return out, nil
}

func tdesBlock(key []byte) (cipher.Block, error) {
	// Go's des.NewTripleDESCipher requires a 24-byte (3-key) key; expand a
	// 2-key (16-byte) TDES key as K1||K2||K1, matching pycryptodome.
	if len(key) == 16 {
		key = append(key, key[:8]...)
	}
	b, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return b, nil
}

func tdesCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	block, err := tdesBlock(key)
	if err != nil {
		return nil, err
	}
	return cbcRun(block, iv, data, true)
}

func tdesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	block, err := tdesBlock(key)
	if err != nil {
		return nil, err
	}
	return cbcRun(block, iv, data, false)
}

func cbcRun(block cipher.Block, iv, data []byte, encrypt bool) ([]byte, error) {
	bs := block.BlockSize()
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, ErrInvalid{Msg: "cbc: data must be a multiple of block size"}
	}
	if len(iv) != bs {
		return nil, ErrInvalid{Msg: "cbc: iv length mismatch"}
	}
	out := make([]byte, len(data))
	if encrypt {
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	} else {
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	}
	return out, nil
}

func tdesECBEncrypt(key, data []byte) ([]byte, error) {
	block, err := tdesBlock(key)
	if err != nil {
		return nil, err
	}
	return ecbTransform(block, data, true)
}

func tdesECBDecrypt(key, data []byte) ([]byte, error) {
	block, err := tdesBlock(key)
	if err != nil {
		return nil, err
	}
	return ecbTransform(block, data, false)
}

// aesGCMSeal encrypts data under AES-GCM with the given 12-byte nonce.
// Returns ciphertext||tag.
func aesGCMSeal(key, nonce, data []byte) ([]byte, []byte, error) {
	block, err := newAESBlock(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, nil, ErrInvalid{Msg: "gcm: nonce must be 12 bytes"}
	}
	sealed := gcm.Seal(nil, nonce, data, nil)
	return sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():], nil
}

// aesGCMOpen decrypts data given ciphertext||tag under AES-GCM.
func aesGCMOpen(key, nonce, sealed []byte) ([]byte, error) {
	block, err := newAESBlock(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalid{Msg: "gcm: nonce must be 12 bytes"}
	}
	return gcm.Open(nil, nonce, sealed, nil)
}
