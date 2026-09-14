// Package hsm defines the crypto-service HSM seam. GP (the software-HSM
// implementation) and future real HSMs (PS, AT) share this interface so the
// provider can be swapped at the composition root without touching the usecase
// layer. All keys travel as LMK-wrapped key blocks.
package hsm

import "context"

// HSM is the abstract hardware-security-module interface. Method signatures
// mirror the real-HSM API surface; GP implements them with the software key
// store so signatures match across providers.
type HSM interface {
	// Ready checks whether the provider can accept operations. Software GP is
	// always ready; hardware adapters should verify their session/connection.
	Ready(ctx context.Context) error

	// KpGen generates an RSA/ECC key pair. Returns the DER public key and the
	// LMK-wrapped private key.
	KpGen(algo, useMode string) (pk, skLMK []byte, err error)

	// GenSign signs msg with the LMK-wrapped private key.
	GenSign(algo string, msg, skLMK []byte) ([]byte, error)

	// Ecdh derives a shared key with a fresh recipient key pair.
	Ecdh(algo string, initPK, sharedInfo []byte, keyType, useMode string) (derivedLMK, kcv, recvPK []byte, err error)

	// ExpKey exports an LMK-wrapped symmetric key under a public key, or returns
	// it untouched when pk is empty (standalone export).
	ExpKey(keyLMK, kcv, pk []byte) ([]byte, error)

	// ExpTr31 re-wraps a key under an export key (ZMK).
	ExpTr31(expKey, key []byte) ([]byte, error)

	// RandGen returns n random bytes.
	RandGen(n int) ([]byte, error)

	// ExpTr34 performs a TR-34 key export (CMS EnvelopedData + SignedData).
	ExpTr34(kbpk, kdhCert, krdCert, kdhSkLMK []byte) ([]byte, error)

	// KeyGen generates a symmetric key and returns it LMK-wrapped with its KCV.
	KeyGen(keyType, useMode, algo string) (keyLMK, kcv []byte, err error)

	// KcvGen computes the key check value for an LMK-wrapped key.
	KcvGen(keyLMK []byte) ([]byte, error)

	// IpekDerive derives an IPEK from a BDK and wraps it under the LMK.
	IpekDerive(bdkLMK, iksn, tk []byte, algo, useMode string) (ipekLMK, kcv []byte, err error)

	// DataEncr encrypts data (PKCS7-padded) under an LMK-wrapped key.
	DataEncr(msg, keyLMK []byte, iv, encrMode, algo string) ([]byte, error)

	// DataDecr decrypts data under an LMK-wrapped key.
	DataDecr(keyLMK []byte, iv string, encrMsg []byte, encrMode, algo string) ([]byte, error)

	// Mac computes a CMAC over msg under an LMK-wrapped key.
	Mac(keyLMK, msg []byte, macMode string) ([]byte, error)

	// TransPin translates a DUKPT-encrypted PIN to a destination key.
	TransPin(keyLMK, destKey, ksn, srcPinblk []byte, pan string) ([]byte, error)

	// Wrap wraps a clear key into a TR-31 key block under kbpk.
	Wrap(algo, header string, kbpk, key []byte) ([]byte, error)

	// Unwrap extracts a clear key from a TR-31 key block under kbpk.
	Unwrap(kbpk, keyKbpk []byte) ([]byte, error)

	// CertCreate builds and signs a certificate from a CSR (TBS → HSM-sign → pack).
	CertCreate(algo string, csr, issuer []byte, certLevel string, skLMK []byte) ([]byte, error)

	// CertRenew rebuilds a certificate with fresh validity (TBS → HSM-sign → pack).
	CertRenew(algo string, cert, issuer []byte, skLMK []byte) ([]byte, error)

	// CrlMgmt builds and signs a CRL (TBS → HSM-sign → pack).
	CrlMgmt(algo string, cert, issuer []byte, skLMK []byte, existingCRL string) ([]byte, error)
}
