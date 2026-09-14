package services

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"cryptosvc/internal/crypto"
	"cryptosvc/internal/dto"
	"cryptosvc/internal/hsm"
)

const (
	statusSuccess  = "success"
	maxRandomBytes = 4096
)

func decodeHex(field, value string) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, crypto.ErrInvalid{Msg: fmt.Sprintf("%s must be valid hexadecimal", field)}
	}
	return b, nil
}

// Crypto is the usecase layer for /v1/crypto. It is transport-agnostic and
// depends only on the HSM seam — the provider (GP/PS/AT) is injected at the
// composition root, so a real HSM can replace the software implementation
// without changing this layer.
type Crypto struct {
	hsm hsm.HSM
}

func NewCrypto(h hsm.HSM) *Crypto { return &Crypto{hsm: h} }

func (c *Crypto) KpGen(ctx context.Context, req dto.KpGenReq) (dto.KpGenResp, error) {
	pk, skLMK, err := c.hsm.KpGen(req.Algo, req.UseMode)
	if err != nil {
		return dto.KpGenResp{}, err
	}
	return dto.KpGenResp{Status: statusSuccess, Pk: b64Encode(pk), SkLmk: b64Encode(skLMK)}, nil
}

func (c *Crypto) GenSign(ctx context.Context, req dto.SignReq) (dto.SignResp, error) {
	msg, err := decodeHex("msg", req.Msg)
	if err != nil {
		return dto.SignResp{}, err
	}
	skLMK, err := b64Decode(req.SkLmk)
	if err != nil {
		return dto.SignResp{}, err
	}
	sig, err := c.hsm.GenSign(req.Algo, msg, skLMK)
	if err != nil {
		return dto.SignResp{}, err
	}
	return dto.SignResp{Status: statusSuccess, Signature: hex.EncodeToString(sig)}, nil
}

func (c *Crypto) Ecdh(ctx context.Context, req dto.EcdhReq) (dto.EcdhResp, error) {
	initPK, err := b64Decode(req.EphPk)
	if err != nil {
		return dto.EcdhResp{}, err
	}
	shared, err := decodeHex("shared_info", req.SharedInfo)
	if err != nil {
		return dto.EcdhResp{}, err
	}
	derived, kcv, recvPK, err := c.hsm.Ecdh(req.Algo, initPK, shared, req.KeyType, req.UseMode)
	if err != nil {
		return dto.EcdhResp{}, err
	}
	return dto.EcdhResp{
		Status:     statusSuccess,
		DerivedKey: b64Encode(derived),
		Kcv:        hex.EncodeToString(kcv),
		RecpEphPk:  b64Encode(recvPK),
	}, nil
}

func (c *Crypto) ExpKey(ctx context.Context, req dto.ExpKeyReq) (dto.ExpKeyResp, error) {
	keyLMK, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.ExpKeyResp{}, err
	}
	var pk []byte
	if req.Pk != "" {
		pk, err = b64Decode(req.Pk)
		if err != nil {
			return dto.ExpKeyResp{}, err
		}
	}
	kcv, err := decodeHex("kcv", req.Kcv)
	if err != nil {
		return dto.ExpKeyResp{}, err
	}
	out, err := c.hsm.ExpKey(keyLMK, kcv, pk)
	if err != nil {
		return dto.ExpKeyResp{}, err
	}
	return dto.ExpKeyResp{Status: statusSuccess, KeyPk: b64Encode(out)}, nil
}

func (c *Crypto) ExpTr31(ctx context.Context, req dto.ExpTr31Req) (dto.ExpTr31Resp, error) {
	expKey, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.ExpTr31Resp{}, err
	}
	key, err := b64Decode(req.ZmkLmk)
	if err != nil {
		return dto.ExpTr31Resp{}, err
	}
	blob, err := c.hsm.ExpTr31(expKey, key)
	if err != nil {
		return dto.ExpTr31Resp{}, err
	}
	return dto.ExpTr31Resp{Status: statusSuccess, KeyZmk: b64Encode(blob)}, nil
}

func (c *Crypto) RandGen(ctx context.Context, req dto.RandGenReq) (dto.RandGenResp, error) {
	n, err := strconv.Atoi(req.Len)
	if err != nil || n < 0 || n > maxRandomBytes {
		return dto.RandGenResp{}, crypto.ErrInvalid{Msg: fmt.Sprintf("len must be between 0 and %d", maxRandomBytes)}
	}
	b, err := c.hsm.RandGen(n)
	if err != nil {
		return dto.RandGenResp{}, err
	}
	return dto.RandGenResp{Status: statusSuccess, RandNo: hex.EncodeToString(b)}, nil
}

func (c *Crypto) ExpTr34(ctx context.Context, req dto.ExpTr34Req) (dto.ExpTr34Resp, error) {
	kbpk, err := b64Decode(req.Kbpk)
	if err != nil {
		return dto.ExpTr34Resp{}, err
	}
	kdhCert, err := b64Decode(req.KdhCert)
	if err != nil {
		return dto.ExpTr34Resp{}, err
	}
	krdCert, err := b64Decode(req.KrdCert)
	if err != nil {
		return dto.ExpTr34Resp{}, err
	}
	kdhSk, err := b64Decode(req.KdhSkLmk)
	if err != nil {
		return dto.ExpTr34Resp{}, err
	}
	sd, err := c.hsm.ExpTr34(kbpk, kdhCert, krdCert, kdhSk)
	if err != nil {
		return dto.ExpTr34Resp{}, err
	}
	return dto.ExpTr34Resp{Status: statusSuccess, Ed: b64Encode(sd)}, nil
}

func (c *Crypto) KeyGen(ctx context.Context, req dto.KeyGenReq) (dto.KeyGenResp, error) {
	keyLMK, kcv, err := c.hsm.KeyGen(req.KeyType, req.UseMode, req.Algo)
	if err != nil {
		return dto.KeyGenResp{}, err
	}
	return dto.KeyGenResp{Status: statusSuccess, KeyLmk: b64Encode(keyLMK), Kcv: hex.EncodeToString(kcv)}, nil
}

func (c *Crypto) KcvGen(ctx context.Context, req dto.KcvGenReq) (dto.KcvGenResp, error) {
	keyLMK, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.KcvGenResp{}, err
	}
	kcv, err := c.hsm.KcvGen(keyLMK)
	if err != nil {
		return dto.KcvGenResp{}, err
	}
	return dto.KcvGenResp{Status: statusSuccess, Kcv: hex.EncodeToString(kcv)}, nil
}

func (c *Crypto) IpekDerive(ctx context.Context, req dto.IpekDeriveReq) (dto.IpekDeriveResp, error) {
	bdk, err := b64Decode(req.BdkLmk)
	if err != nil {
		return dto.IpekDeriveResp{}, err
	}
	iksn, err := decodeHex("iksn", req.Iksn)
	if err != nil {
		return dto.IpekDeriveResp{}, err
	}
	if len(iksn) != 8 {
		return dto.IpekDeriveResp{}, crypto.ErrInvalid{Msg: "iksn must be exactly 8 bytes"}
	}
	var tk []byte
	if req.Tk != "" {
		return dto.IpekDeriveResp{}, crypto.ErrInvalid{Msg: "tk export is not supported by the GP provider"}
	}
	ipekLMK, kcv, err := c.hsm.IpekDerive(bdk, iksn, tk, req.Algo, req.UseMode)
	if err != nil {
		return dto.IpekDeriveResp{}, err
	}
	return dto.IpekDeriveResp{
		Status:  statusSuccess,
		IpekLmk: b64Encode(ipekLMK),
		IpekTk:  "",
		Kcv:     hex.EncodeToString(kcv),
	}, nil
}

func (c *Crypto) DataEncr(ctx context.Context, req dto.DataEncrReq) (dto.DataEncrResp, error) {
	keyLMK, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.DataEncrResp{}, err
	}
	msg, err := decodeHex("msg", req.Msg)
	if err != nil {
		return dto.DataEncrResp{}, err
	}
	ct, err := c.hsm.DataEncr(msg, keyLMK, req.Iv, req.EncrMode, req.Algo)
	if err != nil {
		return dto.DataEncrResp{}, err
	}
	return dto.DataEncrResp{Status: statusSuccess, EncrMsg: hex.EncodeToString(ct)}, nil
}

func (c *Crypto) DataDecr(ctx context.Context, req dto.DataDecrReq) (dto.DataDecrResp, error) {
	keyLMK, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.DataDecrResp{}, err
	}
	ct, err := decodeHex("encr_msg", req.EncrMsg)
	if err != nil {
		return dto.DataDecrResp{}, err
	}
	pt, err := c.hsm.DataDecr(keyLMK, req.Iv, ct, req.EncrMode, req.Algo)
	if err != nil {
		return dto.DataDecrResp{}, err
	}
	return dto.DataDecrResp{Status: statusSuccess, Msg: hex.EncodeToString(pt)}, nil
}

func (c *Crypto) Mac(ctx context.Context, req dto.MacReq) (dto.MacResp, error) {
	if req.Ksn != "" {
		return dto.MacResp{}, crypto.ErrInvalid{Msg: "ksn-based MAC is not supported by the GP provider"}
	}
	if req.MacMode != string(crypto.MacModeGenerate) {
		return dto.MacResp{}, crypto.ErrInvalid{Msg: "GP supports mac_mode GENERATE only"}
	}
	keyLMK, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.MacResp{}, err
	}
	msg, err := decodeHex("msg", req.Msg)
	if err != nil {
		return dto.MacResp{}, err
	}
	mac, err := c.hsm.Mac(keyLMK, msg, req.MacMode)
	if err != nil {
		return dto.MacResp{}, err
	}
	return dto.MacResp{Status: statusSuccess, MacResp: hex.EncodeToString(mac)}, nil
}

func (c *Crypto) TransPin(ctx context.Context, req dto.TransPinReq) (dto.TransPinResp, error) {
	if req.DestKsn != "" {
		return dto.TransPinResp{}, crypto.ErrInvalid{Msg: "dest_ksn is not supported by the GP provider"}
	}
	keyLMK, err := b64Decode(req.KeyLmk)
	if err != nil {
		return dto.TransPinResp{}, err
	}
	destKey, err := b64Decode(req.DestKey)
	if err != nil {
		return dto.TransPinResp{}, err
	}
	ksn, err := decodeHex("ksn", req.Ksn)
	if err != nil {
		return dto.TransPinResp{}, err
	}
	if len(ksn) != 12 {
		return dto.TransPinResp{}, crypto.ErrInvalid{Msg: "ksn must be exactly 12 bytes"}
	}
	srcPinblk, err := decodeHex("src_pinblk", req.SrcPinblk)
	if err != nil {
		return dto.TransPinResp{}, err
	}
	if len(srcPinblk) != 16 {
		return dto.TransPinResp{}, crypto.ErrInvalid{Msg: "src_pinblk must be exactly 16 bytes"}
	}
	destPinblk, err := c.hsm.TransPin(keyLMK, destKey, ksn, srcPinblk, req.Pan)
	if err != nil {
		return dto.TransPinResp{}, err
	}
	return dto.TransPinResp{Status: statusSuccess, DestPinblk: hex.EncodeToString(destPinblk)}, nil
}

func (c *Crypto) Wrap(ctx context.Context, req dto.WrapReq) (dto.WrapResp, error) {
	kbpk, err := b64Decode(req.Kbpk)
	if err != nil {
		return dto.WrapResp{}, err
	}
	key, err := b64Decode(req.Key)
	if err != nil {
		return dto.WrapResp{}, err
	}
	blob, err := c.hsm.Wrap(req.Algo, req.Header, kbpk, key)
	if err != nil {
		return dto.WrapResp{}, err
	}
	return dto.WrapResp{Status: statusSuccess, KeyKbpk: b64Encode(blob)}, nil
}

func (c *Crypto) Unwrap(ctx context.Context, req dto.UnwrapReq) (dto.UnwrapResp, error) {
	kbpk, err := b64Decode(req.Kbpk)
	if err != nil {
		return dto.UnwrapResp{}, err
	}
	keyKbpk, err := b64Decode(req.KeyKbpk)
	if err != nil {
		return dto.UnwrapResp{}, err
	}
	key, err := c.hsm.Unwrap(kbpk, keyKbpk)
	if err != nil {
		return dto.UnwrapResp{}, err
	}
	return dto.UnwrapResp{Status: statusSuccess, Key: b64Encode(key)}, nil
}
