package services

import (
	"context"
	"encoding/hex"

	"cryptosvc/internal/dto"
	"cryptosvc/internal/hsm"
)

// Server is the usecase layer for the /v1/serv PKI operations. It depends only
// on the HSM seam; the provider performs the TBS build → HSM-sign → pack.
type Server struct {
	hsm hsm.HSM
}

func NewServer(h hsm.HSM) *Server { return &Server{hsm: h} }

func (s *Server) CertCreate(ctx context.Context, req dto.CertCreateReq) (dto.CertResp, error) {
	csr, err := b64Decode(req.Csr)
	if err != nil {
		return dto.CertResp{}, err
	}
	var issuer []byte
	if req.IssuerCert != "" {
		issuer, err = b64Decode(req.IssuerCert)
		if err != nil {
			return dto.CertResp{}, err
		}
	}
	skLMK, err := b64Decode(req.SkLmk)
	if err != nil {
		return dto.CertResp{}, err
	}
	cert, err := s.hsm.CertCreate(req.Algo, csr, issuer, req.CertLevel, skLMK)
	if err != nil {
		return dto.CertResp{}, err
	}
	return dto.CertResp{Status: statusSuccess, Cert: b64Encode(cert)}, nil
}

func (s *Server) CertRenew(ctx context.Context, req dto.CertUpdateReq) (dto.CertResp, error) {
	certDER, err := b64Decode(req.Cert)
	if err != nil {
		return dto.CertResp{}, err
	}
	issuer, err := b64Decode(req.IssuerCert)
	if err != nil {
		return dto.CertResp{}, err
	}
	skLMK, err := b64Decode(req.SkLmk)
	if err != nil {
		return dto.CertResp{}, err
	}
	cert, err := s.hsm.CertRenew(req.Algo, certDER, issuer, skLMK)
	if err != nil {
		return dto.CertResp{}, err
	}
	return dto.CertResp{Status: statusSuccess, Cert: b64Encode(cert)}, nil
}

func (s *Server) CrlMgmt(ctx context.Context, req dto.CrlMgmtReq) (dto.CrlMgmtResp, error) {
	certDER, err := b64Decode(req.Cert)
	if err != nil {
		return dto.CrlMgmtResp{}, err
	}
	issuer, err := b64Decode(req.IssuerCert)
	if err != nil {
		return dto.CrlMgmtResp{}, err
	}
	skLMK, err := b64Decode(req.SkLmk)
	if err != nil {
		return dto.CrlMgmtResp{}, err
	}
	existing := ""
	if req.Crl != "" {
		b, err := b64Decode(req.Crl)
		if err != nil {
			return dto.CrlMgmtResp{}, err
		}
		existing = hex.EncodeToString(b)
	}
	crl, err := s.hsm.CrlMgmt(req.Algo, certDER, issuer, skLMK, existing)
	if err != nil {
		return dto.CrlMgmtResp{}, err
	}
	return dto.CrlMgmtResp{Status: statusSuccess, Crl: b64Encode(crl)}, nil
}
