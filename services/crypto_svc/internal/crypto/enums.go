package crypto

import "fmt"

// Algo is the API algorithm string enum.
type Algo string

const (
	AlgoA128  Algo = "A128"
	AlgoA192  Algo = "A192"
	AlgoA256  Algo = "A256"
	AlgoTDES  Algo = "TDES"
	AlgoECP256 Algo = "ECP256"
	AlgoECP384 Algo = "ECP384"
	AlgoECP521 Algo = "ECP521"
	AlgoR2K   Algo = "R2K"
	AlgoR3K   Algo = "R3K"
	AlgoR4K   Algo = "R4K"
)

// symmetric reports whether algo is an AES/TDES symmetric algorithm.
func (a Algo) symmetric() bool {
	return a == AlgoA128 || a == AlgoA192 || a == AlgoA256 || a == AlgoTDES
}

// IsRSA reports whether algo is an RSA algorithm.
func (a Algo) IsRSA() bool { return a.rsaAlgo() }

// IsEC reports whether algo is an elliptic-curve algorithm.
func (a Algo) IsEC() bool { return a.ecdsaAlgo() }

// IsSymmetric reports whether algo is a symmetric algorithm.
func (a Algo) IsSymmetric() bool { return a.symmetric() }

// ecdsaAlgo reports whether algo is an EC algorithm.
func (a Algo) ecdsaAlgo() bool { return a == AlgoECP256 || a == AlgoECP384 || a == AlgoECP521 }

// rsaAlgo reports whether algo is an RSA algorithm.
func (a Algo) rsaAlgo() bool { return a == AlgoR2K || a == AlgoR3K || a == AlgoR4K }

// keyLenBytes returns the key length in bytes for symmetric algos.
func (a Algo) keyLenBytes() (int, error) {
	switch a {
	case AlgoA128, AlgoTDES:
		return 16, nil
	case AlgoA192:
		return 24, nil
	case AlgoA256:
		return 32, nil
	}
	return 0, fmt.Errorf("%w: %s is not a symmetric algo", ErrInvalid{}, a)
}

// EncrMode is the API encryption-mode string enum.
type EncrMode string

const (
	EncrModeCBC    EncrMode = "CBC"
	EncrModeECB    EncrMode = "ECB"
	EncrModeCBCPad EncrMode = "CBC_PAD"
	EncrModeGCM    EncrMode = "GCM"
)

// UseMode is the API key-usage string enum.
type UseMode string

const (
	UseModeDeriv UseMode = "DERIV"
	UseModeNoRes UseMode = "NORES"
	UseModeBoth  UseMode = "BOTH"
	UseModeEncr  UseMode = "ENCR"
	UseModeDecr  UseMode = "DECR"
	UseModeGen   UseMode = "GEN"
	UseModeVerif UseMode = "VERIF"
	UseModeComb  UseMode = "COMB"
	UseModeSign  UseMode = "SIGN"
)

// KeyType is the API key-type string enum.
type KeyType string

const (
	KeyTypeZPK  KeyType = "ZPK"
	KeyTypePVK  KeyType = "PVK"
	KeyTypeCVK  KeyType = "CVK"
	KeyTypeMKAC KeyType = "MKAC"
	KeyTypeBDK  KeyType = "BDK"
	KeyTypeZMK  KeyType = "ZMK"
	KeyTypeTMK  KeyType = "TMK"
	KeyTypeTEK  KeyType = "TEK"
	KeyTypeDEK  KeyType = "DEK"
	KeyTypePEK  KeyType = "PEK"
	KeyTypeMEK  KeyType = "MEK"
	KeyTypeIPEK KeyType = "IPEK"
)

// MacMode is the API MAC-mode string enum.
type MacMode string

const (
	MacModeGenerate MacMode = "GENERATE"
	MacModeVerify   MacMode = "VERIFY"
)

// CertLevel is the API certificate-level string enum.
type CertLevel string

const (
	CertLevelRootCA CertLevel = "ROOT_CA"
	CertLevelIntCA  CertLevel = "INT_CA"
	CertLevelLeaf   CertLevel = "LEAF"
)