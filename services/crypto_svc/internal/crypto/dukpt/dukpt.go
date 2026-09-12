// Package dukpt implements host-side AES DUKPT (Derived Unique Key Per
// Transaction) key derivation per ANSI X9.24-3-2017.
//
// This implementation is based on the reference implementation provided by the
// Accredited Standards Committee X9 (ASC X9) for ANSI X9.24-3-2017.
//
// Reference Implementation Source:
// - X9.24 Part 3 Test Vectors: https://x9.org/standards/x9-24-part-3-test-vectors/
// - Python Source Code: https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Python-Source-20180129-1.pdf
//
// Original X9 Disclaimer:
// "The information is provided 'as is' without warranty of any kind. X9 does
// not accept any responsibility or liability for the accuracy, content,
// completeness, or reliability of the computer code and information contained
// on this page and website."
//
// This implementation has been modified from the original X9 reference
// implementation to integrate with the fmcrypto Service architecture and
// requirements.
//
// Copyright (c) 2025 fmcrypto Service
package dukpt

import (
	"crypto/aes"
	"fmt"
)

// KeyType enumerates the supported DUKPT key algorithms (X9.24-3 §B.3.1).
type KeyType int

const (
	TwoTDEA   KeyType = 0
	ThreeTDEA KeyType = 1
	AES128    KeyType = 2
	AES192    KeyType = 3
	AES256    KeyType = 4
)

// KeyUsage enumerates the derived-key purposes (X9.24-3 §B.3.1).
type KeyUsage int

const (
	KeyEncryptionKey      KeyUsage = 0x0002
	PINEncryption         KeyUsage = 0x1000
	MessageAuthGen        KeyUsage = 0x2000
	MessageAuthVerify     KeyUsage = 0x2001
	MessageAuthBothWays   KeyUsage = 0x2002
	DataEncryptionEncrypt KeyUsage = 0x3000
	DataEncryptionDecrypt KeyUsage = 0x3001
	DataEncryptionBoth    KeyUsage = 0x3002
	KeyDerivation         KeyUsage = 0x8000
	KeyDerivationInitial  KeyUsage = 9
)

type derivationPurpose int

const (
	purposeInitialKey derivationPurpose = 0
	purposeWorkingKey derivationPurpose = 1
)

// Deriver derives initial and transaction keys from a BDK.
type Deriver struct{}

// DeriveInitialKey derives the initial key for an initial-key ID from a BDK.
func (Deriver) DeriveInitialKey(bdk []byte, keyType KeyType, initialKeyID []byte) ([]byte, error) {
	d := createDerivationData(purposeInitialKey, KeyDerivationInitial, keyType, initialKeyID, 0)
	return deriveKey(bdk, keyType, d)
}

// DeriveWorkingKey derives the derivation key, derivation data, and working key
// for a transaction identified by counter.
func (Deriver) DeriveWorkingKey(initialKey []byte, deriveKeyType KeyType,
	workingKeyUsage KeyUsage, workingKeyType KeyType,
	initialKeyID []byte, counter uint32) (derivationKey, derivationData, workingKey []byte, err error) {
	var mask uint32 = 0x80000000
	workingCounter := uint32(0)
	derivationKey = initialKey

	for mask > 0 {
		if mask&counter != 0 {
			workingCounter |= mask
			d := createDerivationData(purposeWorkingKey, KeyDerivation, deriveKeyType, initialKeyID, workingCounter)
			dk, err := deriveKey(derivationKey, deriveKeyType, d)
			if err != nil {
				return nil, nil, nil, err
			}
			derivationKey = dk
		}
		mask >>= 1
	}

	d := createDerivationData(purposeWorkingKey, workingKeyUsage, workingKeyType, initialKeyID, counter)
	wk, err := deriveKey(derivationKey, workingKeyType, d)
	if err != nil {
		return nil, nil, nil, err
	}
	return derivationKey, d, wk, nil
}

// HostDeriveWorkingKey derives a transaction working key directly from a BDK.
func (Deriver) HostDeriveWorkingKey(bdk []byte, deriveKeyType KeyType,
	workingKeyUsage KeyUsage, workingKeyType KeyType,
	initialKeyID []byte, counter uint32) ([]byte, []byte, []byte, error) {
	ik, err := (Deriver{}).DeriveInitialKey(bdk, deriveKeyType, initialKeyID)
	if err != nil {
		return nil, nil, nil, err
	}
	return (Deriver{}).DeriveWorkingKey(ik, deriveKeyType, workingKeyUsage, workingKeyType, initialKeyID, counter)
}

// --- internals (X9.24-3 §B.4) ---

func keyLength(t KeyType) int {
	switch t {
	case TwoTDEA:
		return 128
	case ThreeTDEA:
		return 192
	case AES128:
		return 128
	case AES192:
		return 192
	case AES256:
		return 256
	}
	return 0
}

// aesECBEncrypt encrypts a 16-byte block. ECB is used only for key derivation,
// as required by the standard — never for data encryption.
func aesECBEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("dukpt: invalid key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != block.BlockSize() {
		return nil, fmt.Errorf("dukpt: input must be one block")
	}
	out := make([]byte, block.BlockSize())
	block.Encrypt(out, plaintext)
	return out, nil
}

func intToBytes(x uint32) []byte {
	return []byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}
}

func setKeyUsage(u KeyUsage, d []byte) {
	switch u {
	case KeyEncryptionKey:
		d[2], d[3] = 0, 2
	case PINEncryption:
		d[2], d[3] = 16, 0
	case MessageAuthGen:
		d[2], d[3] = 32, 0
	case MessageAuthVerify:
		d[2], d[3] = 32, 1
	case MessageAuthBothWays:
		d[2], d[3] = 32, 2
	case DataEncryptionEncrypt:
		d[2], d[3] = 48, 0
	case DataEncryptionDecrypt:
		d[2], d[3] = 48, 1
	case DataEncryptionBoth:
		d[2], d[3] = 48, 2
	case KeyDerivation:
		d[2], d[3] = 128, 0
	case KeyDerivationInitial:
		d[2], d[3] = 128, 1
	}
}

func setKeyType(t KeyType, d []byte) {
	switch t {
	case TwoTDEA:
		d[4], d[5] = 0, 0
	case ThreeTDEA:
		d[4], d[5] = 0, 1
	case AES128:
		d[4], d[5] = 0, 2
	case AES192:
		d[4], d[5] = 0, 3
	case AES256:
		d[4], d[5] = 0, 4
	}
}

// deriveKey implements the AES DUKPT key derivation function (§B.4.1).
func deriveKey(derivationKey []byte, keyType KeyType, derivationData []byte) ([]byte, error) {
	l := keyLength(keyType)
	n := (l + 127) / 128
	out := make([]byte, 0, n*16)
	for i := 1; i <= n; i++ {
		derivationData[1] = byte(i)
		block, err := aesECBEncrypt(derivationKey, derivationData)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out[:l/8], nil
}

func createDerivationData(purpose derivationPurpose, usage KeyUsage,
	derivedType KeyType, initialKeyID []byte, counter uint32) []byte {
	d := make([]byte, 16)
	d[0], d[1] = 1, 1
	setKeyUsage(usage, d)
	setKeyType(derivedType, d)
	switch purpose {
	case purposeInitialKey:
		copy(d[8:16], initialKeyID[0:8])
	case purposeWorkingKey:
		copy(d[8:12], initialKeyID[4:8])
		copy(d[12:16], intToBytes(counter))
	}
	return d
}
