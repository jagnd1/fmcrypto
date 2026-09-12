package crypto

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"math/big"
)

// Asymmetric key operations. Keys are
// DER-serialized (SPKI for public, PKCS#8 for private) and the private key is
// held under the LMK as a TR-31 block.

// GenKP generates an RSA/ECC key pair. Returns (pkDER, skLMK).
func GenKP(algo Algo, lmk []byte) ([]byte, []byte, error) {
	var (
		skDER []byte
		pk    any
		err   error
	)
	switch {
	case algo.rsaAlgo():
		bits := 2048
		switch algo {
		case AlgoR3K:
			bits = 3072
		case AlgoR4K:
			bits = 4096
		}
		key, e := rsa.GenerateKey(rand.Reader, bits)
		if e != nil {
			return nil, nil, e
		}
		pk = &key.PublicKey
		skDER, err = x509.MarshalPKCS8PrivateKey(key)
	case algo.ecdsaAlgo():
		curve, e := ecCurve(algo)
		if e != nil {
			return nil, nil, e
		}
		key, e := ecdsa.GenerateKey(curve, rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		pk = &key.PublicKey
		skDER, err = x509.MarshalPKCS8PrivateKey(key)
	default:
		return nil, nil, ErrInvalid{Msg: "invalid algo for keypair"}
	}
	if err != nil {
		return nil, nil, err
	}
	pkDER, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	skLMK, err := tr31Wrap(lmk, skDER, headerAsym, 0)
	if err != nil {
		return nil, nil, err
	}
	return pkDER, []byte(skLMK), nil
}

func ecCurve(algo Algo) (elliptic.Curve, error) {
	switch algo {
	case AlgoECP256:
		return elliptic.P256(), nil
	case AlgoECP384:
		return elliptic.P384(), nil
	case AlgoECP521:
		return elliptic.P521(), nil
	}
	return nil, ErrInvalid{Msg: "invalid ec algo"}
}

func parsePK(pkDER []byte) (any, error) {
	k, err := x509.ParsePKIXPublicKey(pkDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return k, nil
}

func parseSK(skDER []byte) (any, error) {
	k, err := x509.ParsePKCS8PrivateKey(skDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return k, nil
}

// hashFor returns the hash for the algo (R2K/ECP256→SHA256, R3K/ECP384→SHA384,
// R4K/ECP521→SHA512).
func hashFor(algo Algo) (hash.Hash, error) {
	switch algo {
	case AlgoR2K, AlgoECP256:
		return sha256.New(), nil
	case AlgoR3K, AlgoECP384:
		return sha512.New384(), nil
	case AlgoR4K, AlgoECP521:
		return sha512.New(), nil
	}
	return nil, ErrInvalid{Msg: "invalid sign algo"}
}

func digest(algo Algo, data []byte) ([]byte, error) {
	h, err := hashFor(algo)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// AsymSign signs data with the LMK-wrapped private key. RSA → PKCS#1 v1.5,
// ECDSA → DER-encoded.
func AsymSign(algo Algo, lmk []byte, skLMK string, data []byte) ([]byte, error) {
	d, err := digest(algo, data)
	if err != nil {
		return nil, err
	}
	return AsymSignDigest(algo, lmk, skLMK, d)
}

// AsymSignDigest signs an already-hashed digest with the LMK-wrapped private
// key (used by the x509 signer, which hashes the TBS itself).
func AsymSignDigest(algo Algo, lmk []byte, skLMK string, digest []byte) ([]byte, error) {
	skDER, err := UnwrapKey(algo, lmk, skLMK)
	if err != nil {
		return nil, err
	}
	sk, err := parseSK(skDER)
	if err != nil {
		return nil, err
	}
	switch k := sk.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, rsaHash(algo), digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest)
	}
	return nil, ErrInvalid{Msg: "unsupported private key type"}
}

func rsaHash(algo Algo) crypto.Hash {
	switch algo {
	case AlgoR2K:
		return crypto.SHA256
	case AlgoR3K:
		return crypto.SHA384
	case AlgoR4K:
		return crypto.SHA512
	}
	return 0
}

// PkEncrypt RSA-encrypts data (PKCS#1 v1.5) under a DER public key.
func PkEncrypt(pkDER, data []byte) ([]byte, error) {
	pk, err := parsePK(pkDER)
	if err != nil {
		return nil, err
	}
	rsaPK, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalid{Msg: "pk encrypt requires rsa key"}
	}
	return rsa.EncryptPKCS1v15(rand.Reader, rsaPK, data)
}

// ExpKey exports an LMK-wrapped symmetric key under an RSA public key, or
// returns it untouched when pk is empty (standalone export).
func ExpKey(algo Algo, lmk []byte, keyLMK, kcv []byte, pk []byte) ([]byte, error) {
	if len(pk) == 0 {
		return keyLMK, nil
	}
	clearKey, err := UnwrapKey(AlgoA128, lmk, string(keyLMK))
	if err != nil {
		return nil, err
	}
	return PkEncrypt(pk, clearKey)
}

// Ecdh derives a shared key. recvSK is the LMK-wrapped local EC private key,
// initPK is the peer DER public key. Returns the derived key wrapped under the
// LMK (AES-128) and the peer public key (re-exported unchanged).
func Ecdh(algo Algo, lmk []byte, recvSK string, recvPK, initPK []byte) ([]byte, []byte, error) {
	if algo.rsaAlgo() {
		return nil, nil, ErrInvalid{Msg: "rsa not supported for ecdh"}
	}
	skDER, err := UnwrapKey(algo, lmk, recvSK)
	if err != nil {
		return nil, nil, err
	}
	sk, err := parseSK(skDER)
	if err != nil {
		return nil, nil, err
	}
	ecSK, ok := sk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, ErrInvalid{Msg: "ecdh requires ec private key"}
	}
	pk, err := parsePK(initPK)
	if err != nil {
		return nil, nil, err
	}
	ecPK, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, ErrInvalid{Msg: "ecdh requires ec public key"}
	}

	curve := ecSK.Curve
	privECDH, err := ecdsaToECDH(ecSK)
	if err != nil {
		return nil, nil, err
	}
	pubECDH, err := ecdhPubFromCurve(curve, ecPK.X, ecPK.Y)
	if err != nil {
		return nil, nil, err
	}
	secret, err := privECDH.ECDH(pubECDH)
	if err != nil {
		return nil, nil, err
	}

	keyLen := 16 // AES-128 session key
	derived := ecdhHKDF(secret, keyLen)
	blob, err := WrapKey(AlgoA128, lmk, derived, "")
	if err != nil {
		return nil, nil, err
	}
	return []byte(blob), recvPK, nil
}

func ecdsaToECDH(k *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	curve, err := ecdhCurveFor(k.Curve)
	if err != nil {
		return nil, err
	}
	pk, err := curve.NewPrivateKey(k.D.FillBytes(make([]byte, (k.Curve.Params().BitSize+7)/8)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return pk, nil
}

func ecdhPubFromCurve(curve elliptic.Curve, x, y *big.Int) (*ecdh.PublicKey, error) {
	c, err := ecdhCurveFor(curve)
	if err != nil {
		return nil, err
	}
	fieldSize := (curve.Params().BitSize + 7) / 8
	buf := make([]byte, 1+2*fieldSize)
	buf[0] = 4
	x.FillBytes(buf[1 : 1+fieldSize])
	y.FillBytes(buf[1+fieldSize : 1+2*fieldSize])
	pk, err := c.NewPublicKey(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	return pk, nil
}

func ecdhCurveFor(curve elliptic.Curve) (ecdh.Curve, error) {
	switch curve {
	case elliptic.P256():
		return ecdh.P256(), nil
	case elliptic.P384():
		return ecdh.P384(), nil
	case elliptic.P521():
		return ecdh.P521(), nil
	}
	return nil, ErrInvalid{Msg: "unsupported curve for ecdh"}
}