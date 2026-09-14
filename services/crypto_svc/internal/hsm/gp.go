package hsm

import (
	"context"
	"encoding/hex"
	"fmt"

	"cryptosvc/internal/crypto"
	"cryptosvc/internal/crypto/dukpt"
)

// GP is the software-HSM implementation of the HSM seam. It keeps keys
// LMK-wrapped (TR-31 vD) at all times, mirroring a real HSM, and implements the
// exact same API surface as the PS/AT hardware providers.
type GP struct {
	lmk []byte
}

func NewGP(lmk []byte) *GP {
	if len(lmk) == 0 {
		lmk = crypto.Lmk(nil)
	}
	return &GP{lmk: lmk}
}

func (g *GP) Ready(context.Context) error { return nil }

func (g *GP) KpGen(algo, _ string) ([]byte, []byte, error) {
	pk, skLMK, err := crypto.GenKP(crypto.Algo(algo), g.lmk)
	return pk, skLMK, err
}

func (g *GP) GenSign(algo string, msg, skLMK []byte) ([]byte, error) {
	return crypto.AsymSign(crypto.Algo(algo), g.lmk, string(skLMK), msg)
}

func (g *GP) Ecdh(algo string, initPK, _ []byte, _, _ string) ([]byte, []byte, []byte, error) {
	recvPK, recvSK, err := crypto.GenKP(crypto.AlgoECP256, g.lmk)
	if err != nil {
		return nil, nil, nil, err
	}
	derived, recvPKOut, err := crypto.Ecdh(crypto.Algo(algo), g.lmk, string(recvSK), recvPK, initPK)
	if err != nil {
		return nil, nil, nil, err
	}
	kcv, err := crypto.GetKCV(crypto.AlgoA128, g.lmk, string(derived))
	if err != nil {
		return nil, nil, nil, err
	}
	return derived, kcv, recvPKOut, nil
}

func (g *GP) ExpKey(keyLMK, kcv, pk []byte) ([]byte, error) {
	return crypto.ExpKey(crypto.AlgoA128, g.lmk, keyLMK, kcv, pk)
}

func (g *GP) ExpTr31(expKey, key []byte) ([]byte, error) {
	if len(key) < 12 {
		return nil, crypto.ErrInvalid{Msg: "key_lmk is too short to contain a TR-31 header"}
	}
	expKeyClear, err := crypto.UnwrapKey(crypto.AlgoA128, g.lmk, string(expKey))
	if err != nil {
		return nil, err
	}
	keyClear, err := crypto.UnwrapKey(crypto.AlgoA128, g.lmk, string(key))
	if err != nil {
		return nil, err
	}
	header := string(key[0]) + string(key[5:12])
	blob, err := crypto.WrapKey(crypto.AlgoA128, expKeyClear, keyClear, header)
	if err != nil {
		return nil, err
	}
	return []byte(blob), nil
}

func (g *GP) RandGen(n int) ([]byte, error) {
	b, err := crypto.RandomBytes(n)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (g *GP) ExpTr34(kbpk, kdhCert, krdCert, kdhSkLMK []byte) ([]byte, error) {
	return crypto.Tr34Export(g.lmk, kbpk, krdCert, kdhCert, string(kdhSkLMK))
}

func (g *GP) KeyGen(_, _, algo string) ([]byte, []byte, error) {
	blob, err := crypto.GenKey(crypto.Algo(algo), g.lmk)
	if err != nil {
		return nil, nil, err
	}
	kcv, err := crypto.GetKCV(crypto.Algo(algo), g.lmk, blob)
	if err != nil {
		return nil, nil, err
	}
	return []byte(blob), kcv, nil
}

func (g *GP) KcvGen(keyLMK []byte) ([]byte, error) {
	return crypto.GetKCV(crypto.AlgoA128, g.lmk, string(keyLMK))
}

func (g *GP) IpekDerive(bdkLMK, iksn, _ []byte, algo, _ string) ([]byte, []byte, error) {
	if len(iksn) != 8 {
		return nil, nil, crypto.ErrInvalid{Msg: "iksn must be exactly 8 bytes"}
	}
	bdkClear, err := crypto.UnwrapKey(crypto.Algo(algo), g.lmk, string(bdkLMK))
	if err != nil {
		return nil, nil, err
	}
	keyType, err := dukptKeyType(crypto.Algo(algo))
	if err != nil {
		return nil, nil, err
	}
	ipekClear, err := (dukpt.Deriver{}).DeriveInitialKey(bdkClear, keyType, iksn[:8])
	if err != nil {
		return nil, nil, err
	}
	ipekBlob, err := crypto.WrapKey(crypto.Algo(algo), g.lmk, ipekClear, "DB1AX00E")
	if err != nil {
		return nil, nil, err
	}
	kcv, err := crypto.GetKCV(crypto.Algo(algo), g.lmk, ipekBlob)
	if err != nil {
		return nil, nil, err
	}
	return []byte(ipekBlob), kcv, nil
}

func (g *GP) DataEncr(msg, keyLMK []byte, iv, mode, algo string) ([]byte, error) {
	return crypto.Encrypt(crypto.Algo(algo), g.lmk, crypto.EncrMode(mode), string(keyLMK), []byte(iv), msg)
}

func (g *GP) DataDecr(keyLMK []byte, iv string, encrMsg []byte, mode, algo string) ([]byte, error) {
	return crypto.Decrypt(crypto.Algo(algo), g.lmk, crypto.EncrMode(mode), string(keyLMK), []byte(iv), encrMsg)
}

func (g *GP) Mac(keyLMK, msg []byte, mode string) ([]byte, error) {
	if mode != string(crypto.MacModeGenerate) {
		return nil, crypto.ErrInvalid{Msg: "GP supports mac_mode GENERATE only"}
	}
	mac, err := crypto.Sign(crypto.AlgoA128, g.lmk, string(keyLMK), msg)
	if err != nil {
		return nil, err
	}
	if len(mac) > 3 {
		mac = mac[:3]
	}
	return mac, nil
}

func (g *GP) TransPin(keyLMK, destKey, ksn, srcPinblk []byte, pan string) ([]byte, error) {
	if len(ksn) != 12 {
		return nil, crypto.ErrInvalid{Msg: "ksn must be exactly 12 bytes"}
	}
	if len(srcPinblk) != 16 {
		return nil, crypto.ErrInvalid{Msg: "src_pinblk must be exactly 16 bytes"}
	}
	ipekClear, err := crypto.UnwrapKey(crypto.AlgoA128, g.lmk, string(keyLMK))
	if err != nil {
		return nil, err
	}
	initialKeyID := ksn[:8]
	counter := uint32(0)
	for _, b := range ksn[9:] {
		counter = counter<<8 | uint32(b)
	}
	_, _, wkClear, err := (dukpt.Deriver{}).DeriveWorkingKey(
		ipekClear, dukpt.AES128, dukpt.PINEncryption, dukpt.AES128, initialKeyID, counter)
	if err != nil {
		return nil, err
	}
	wkLMK, err := crypto.WrapKey(crypto.AlgoA128, g.lmk, wkClear, "")
	if err != nil {
		return nil, err
	}
	blockB, err := crypto.Decrypt(crypto.AlgoA128, g.lmk, crypto.EncrModeECB, wkLMK, nil, srcPinblk)
	if err != nil {
		return nil, err
	}
	panField, err := panField(pan)
	if err != nil {
		return nil, err
	}
	blockA := xorBytes(blockB, panField)
	pinField, err := crypto.Decrypt(crypto.AlgoA128, g.lmk, crypto.EncrModeECB, wkLMK, nil, blockA)
	if err != nil {
		return nil, err
	}
	pinClear, err := parsePinField(pinField)
	if err != nil {
		return nil, err
	}
	pinBlkClear, err := crypto.EncodePinblockISO0(pinClear, pan)
	if err != nil {
		return nil, err
	}
	return crypto.Encrypt(crypto.AlgoTDES, g.lmk, crypto.EncrModeECB, string(destKey), make([]byte, 8), pinBlkClear)
}

func (g *GP) Wrap(algo, header string, kbpk, key []byte) ([]byte, error) {
	if header == "" {
		a := crypto.Algo(algo)
		if a.IsRSA() || a.IsEC() {
			header = "DS0ES00E"
		} else {
			header = "DD0AB00E"
		}
	}
	blob, err := crypto.WrapKey(crypto.Algo(algo), kbpk, key, header)
	if err != nil {
		return nil, err
	}
	return []byte(blob), nil
}

func (g *GP) Unwrap(kbpk, keyKbpk []byte) ([]byte, error) {
	return crypto.UnwrapKey("", kbpk, string(keyKbpk))
}

func (g *GP) CertCreate(algo string, csr, issuer []byte, certLevel string, skLMK []byte) ([]byte, error) {
	tbs, signAlgo, err := crypto.CertTbsBuild(csr, issuer, crypto.CertLevel(certLevel), crypto.Algo(algo))
	if err != nil {
		return nil, err
	}
	sig, err := crypto.AsymSign(signAlgo, g.lmk, string(skLMK), tbs)
	if err != nil {
		return nil, err
	}
	return crypto.CertPack(tbs, sig, signAlgo)
}

func (g *GP) CertRenew(algo string, cert, issuer []byte, skLMK []byte) ([]byte, error) {
	tbs, signAlgo, err := crypto.CertRenewTbs(cert, issuer, crypto.Algo(algo))
	if err != nil {
		return nil, err
	}
	sig, err := crypto.AsymSign(signAlgo, g.lmk, string(skLMK), tbs)
	if err != nil {
		return nil, err
	}
	return crypto.CertPack(tbs, sig, signAlgo)
}

func (g *GP) CrlMgmt(algo string, cert, issuer []byte, skLMK []byte, existingCRL string) ([]byte, error) {
	tbs, signAlgo, err := crypto.CRLTbsBuild(cert, issuer, crypto.Algo(algo), existingCRL)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.AsymSign(signAlgo, g.lmk, string(skLMK), tbs)
	if err != nil {
		return nil, err
	}
	return crypto.CRLPack(tbs, sig, signAlgo)
}

// --- helpers ---

func dukptKeyType(algo crypto.Algo) (dukpt.KeyType, error) {
	switch algo {
	case crypto.AlgoA128:
		return dukpt.AES128, nil
	case crypto.AlgoA192:
		return dukpt.AES192, nil
	case crypto.AlgoA256:
		return dukpt.AES256, nil
	}
	return 0, crypto.ErrInvalid{Msg: fmt.Sprintf("invalid dukpt algo %s", algo)}
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func parsePinField(field []byte) (string, error) {
	hexStr := hex.EncodeToString(field)
	if len(hexStr) < 4 {
		return "", crypto.ErrInvalid{Msg: "pin field too short"}
	}
	pinLen := int(hexStr[1] - '0')
	if pinLen < 4 || pinLen > 16 || 2+pinLen > len(hexStr) {
		return "", crypto.ErrInvalid{Msg: fmt.Sprintf("pin length invalid: %d", pinLen)}
	}
	return hexStr[2 : 2+pinLen], nil
}

func panField(panHex string) ([]byte, error) {
	if len(panHex) < 12 {
		return nil, crypto.ErrInvalid{Msg: "pan must contain at least 12 digits"}
	}
	for _, r := range panHex {
		if r < '0' || r > '9' {
			return nil, crypto.ErrInvalid{Msg: "pan must contain decimal digits only"}
		}
	}
	s := "4" + panHex
	if len(s) > 32 {
		return nil, crypto.ErrInvalid{Msg: "pan field too long"}
	}
	for len(s) < 32 {
		s += "0"
	}
	return hex.DecodeString(s)
}
