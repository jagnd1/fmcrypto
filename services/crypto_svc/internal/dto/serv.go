package dto

// PKI (serv) endpoint request/response models, mirroring the merged
// pki_service-in-crypto endpoints exposed under /v1/serv.

type CertCreateReq struct {
	Csr        string `json:"csr"`
	IssuerCert string `json:"issuer_cert,omitempty"`
	SkLmk      string `json:"sk_lmk"`
	CertLevel  string `json:"cert_level"`
	Algo       string `json:"algo"`
}

type CertUpdateReq struct {
	Cert       string `json:"cert"`
	IssuerCert string `json:"issuer_cert"`
	SkLmk      string `json:"sk_lmk"`
	CertLevel  string `json:"cert_level"`
	Algo       string `json:"algo"`
}

type CertResp struct {
	Status string `json:"status"`
	Cert   string `json:"cert,omitempty"`
}

type CrlMgmtReq struct {
	Cert       string `json:"cert"`
	IssuerCert string `json:"issuer_cert"`
	SkLmk      string `json:"sk_lmk"`
	Algo       string `json:"algo"`
	Crl        string `json:"crl,omitempty"`
}

type CrlMgmtResp struct {
	Status string `json:"status"`
	Crl    string `json:"crl,omitempty"`
}