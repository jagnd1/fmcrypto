package dto

// Crypto endpoint request/response models. All enum-ish fields (algo, use_mode,
// key_type, encr_mode, mac_mode) are validated by the service layer, matching the
// Python API which accepts those as string enums.

type KpGenReq struct {
	Algo    string `json:"algo"`
	UseMode string `json:"use_mode"`
}

type KpGenResp struct {
	Status string  `json:"status"`
	Pk     string  `json:"pk,omitempty"`
	SkLmk  string  `json:"sk_lmk,omitempty"`
}

type SignReq struct {
	Msg   string `json:"msg"`
	SkLmk string `json:"sk_lmk"`
	Algo  string `json:"algo"`
}

type SignResp struct {
	Status    string `json:"status"`
	Signature string `json:"signature,omitempty"`
}

type EcdhReq struct {
	EphPk     string `json:"eph_pk"`
	Algo      string `json:"algo"`
	KeyType   string `json:"key_type"`
	UseMode   string `json:"use_mode"`
	SharedInfo string `json:"shared_info,omitempty"`
}

type EcdhResp struct {
	Status     string `json:"status"`
	DerivedKey string `json:"derived_key,omitempty"`
	Kcv        string `json:"kcv,omitempty"`
	RecpEphPk  string `json:"recp_eph_pk,omitempty"`
}

type ExpKeyReq struct {
	KeyLmk string `json:"key_lmk"`
	Kcv    string `json:"kcv"`
	Pk     string `json:"pk"`
}

type ExpKeyResp struct {
	Status string `json:"status"`
	KeyPk  string `json:"key_pk,omitempty"`
}

type ExpTr31Req struct {
	KeyLmk string `json:"key_lmk"`
	ZmkLmk string `json:"zmk_lmk"`
	Iksn   string `json:"iksn,omitempty"`
}

type ExpTr31Resp struct {
	Status string `json:"status"`
	KeyZmk string `json:"key_zmk,omitempty"`
}

type RandGenReq struct {
	Len string `json:"len"`
}

type RandGenResp struct {
	Status string `json:"status"`
	RandNo string `json:"rand_no,omitempty"`
}

type ExpTr34Req struct {
	Kbpk     string `json:"kbpk"`
	Kcv      string `json:"kcv"`
	KdhCert  string `json:"kdh_cert"`
	KrdCert  string `json:"krd_cert"`
	KdhSkLmk string `json:"kdh_sk_lmk"`
}

type ExpTr34Resp struct {
	Status    string `json:"status"`
	Aa        string `json:"aa,omitempty"`
	Ed        string `json:"ed,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type KeyGenReq struct {
	KeyType string `json:"key_type"`
	UseMode string `json:"use_mode"`
	Algo    string `json:"algo"`
	ExpKey  string `json:"exp_key,omitempty"`
}

type KeyGenResp struct {
	Status string `json:"status"`
	KeyLmk string `json:"key_lmk,omitempty"`
	Kcv    string `json:"kcv,omitempty"`
}

type KcvGenReq struct {
	KeyLmk string `json:"key_lmk"`
}

type KcvGenResp struct {
	Status string `json:"status"`
	Kcv    string `json:"kcv,omitempty"`
}

type IpekDeriveReq struct {
	BdkLmk  string `json:"bdk_lmk"`
	Iksn    string `json:"iksn"`
	Tk      string `json:"tk,omitempty"`
	Algo    string `json:"algo"`
	UseMode string `json:"use_mode"`
}

type IpekDeriveResp struct {
	Status  string `json:"status"`
	IpekLmk string `json:"ipek_lmk,omitempty"`
	IpekTk  string `json:"ipek_tk,omitempty"`
	Kcv     string `json:"kcv,omitempty"`
}

type DataEncrReq struct {
	KeyLmk   string `json:"key_lmk"`
	Ksn      string `json:"ksn,omitempty"`
	Iv       string `json:"iv,omitempty"`
	EncrMode string `json:"encr_mode"`
	Msg      string `json:"msg"`
	Algo     string `json:"algo"`
}

type DataEncrResp struct {
	Status  string `json:"status"`
	EncrMsg string `json:"encr_msg,omitempty"`
}

type DataDecrReq struct {
	KeyLmk   string `json:"key_lmk"`
	Ksn      string `json:"ksn,omitempty"`
	Iv       string `json:"iv,omitempty"`
	EncrMode string `json:"encr_mode"`
	EncrMsg  string `json:"encr_msg"`
	Algo     string `json:"algo"`
}

type DataDecrResp struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
}

type MacReq struct {
	KeyLmk  string `json:"key_lmk"`
	Ksn     string `json:"ksn,omitempty"`
	MacMode string `json:"mac_mode"`
	Msg     string `json:"msg"`
	Mac     string `json:"mac,omitempty"`
}

type MacResp struct {
	Status  string `json:"status"`
	MacResp string `json:"mac_resp,omitempty"`
}

type TransPinReq struct {
	KeyLmk   string `json:"key_lmk"`
	Ksn      string `json:"ksn,omitempty"`
	SrcPinblk string `json:"src_pinblk"`
	DestKey  string `json:"dest_key"`
	DestKsn  string `json:"dest_ksn,omitempty"`
	Pan      string `json:"pan"`
}

type TransPinResp struct {
	Status     string `json:"status"`
	DestPinblk string `json:"dest_pinblk,omitempty"`
}

type WrapReq struct {
	Algo   string `json:"algo"`
	Header string `json:"header,omitempty"`
	Kbpk   string `json:"kbpk"`
	Key    string `json:"key"`
}

type WrapResp struct {
	Status   string `json:"status"`
	KeyKbpk  string `json:"key_kbpk"`
}

type UnwrapReq struct {
	KeyKbpk string `json:"key_kbpk"`
	Kbpk    string `json:"kbpk"`
}

type UnwrapResp struct {
	Status string `json:"status"`
	Key    string `json:"key"`
}