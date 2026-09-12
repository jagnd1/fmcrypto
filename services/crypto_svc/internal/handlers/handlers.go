// Package handlers is the REST transport: decode → authorize → usecase → respond.
package handlers

import (
	"context"
	"net/http"

	"common/httpx"
	"common/respond"

	"cryptosvc/internal/dto"
)

// CryptoService is the usecase seam for /v1/crypto, defined where consumed.
type CryptoService interface {
	KpGen(ctx context.Context, req dto.KpGenReq) (dto.KpGenResp, error)
	GenSign(ctx context.Context, req dto.SignReq) (dto.SignResp, error)
	Ecdh(ctx context.Context, req dto.EcdhReq) (dto.EcdhResp, error)
	ExpKey(ctx context.Context, req dto.ExpKeyReq) (dto.ExpKeyResp, error)
	ExpTr31(ctx context.Context, req dto.ExpTr31Req) (dto.ExpTr31Resp, error)
	RandGen(ctx context.Context, req dto.RandGenReq) (dto.RandGenResp, error)
	ExpTr34(ctx context.Context, req dto.ExpTr34Req) (dto.ExpTr34Resp, error)
	KeyGen(ctx context.Context, req dto.KeyGenReq) (dto.KeyGenResp, error)
	KcvGen(ctx context.Context, req dto.KcvGenReq) (dto.KcvGenResp, error)
	IpekDerive(ctx context.Context, req dto.IpekDeriveReq) (dto.IpekDeriveResp, error)
	DataEncr(ctx context.Context, req dto.DataEncrReq) (dto.DataEncrResp, error)
	DataDecr(ctx context.Context, req dto.DataDecrReq) (dto.DataDecrResp, error)
	Mac(ctx context.Context, req dto.MacReq) (dto.MacResp, error)
	TransPin(ctx context.Context, req dto.TransPinReq) (dto.TransPinResp, error)
	Wrap(ctx context.Context, req dto.WrapReq) (dto.WrapResp, error)
	Unwrap(ctx context.Context, req dto.UnwrapReq) (dto.UnwrapResp, error)
}

// ServerService is the usecase seam for /v1/serv, defined where consumed.
type ServerService interface {
	CertCreate(ctx context.Context, req dto.CertCreateReq) (dto.CertResp, error)
	CertRenew(ctx context.Context, req dto.CertUpdateReq) (dto.CertResp, error)
	CrlMgmt(ctx context.Context, req dto.CrlMgmtReq) (dto.CrlMgmtResp, error)
}

// Authorizer is the authorization seam. Injected at the composition root:
// authz.Policy (production) or authz.PermitAll (dev/no IdP).
type Authorizer interface {
	Authorize(ctx context.Context, perm string) error
}

type Server struct {
	crypto CryptoService
	serv   ServerService
	authz  Authorizer
}

func New(crypto CryptoService, serv ServerService, a Authorizer) *Server {
	return &Server{crypto: crypto, serv: serv, authz: a}
}

// authorize delegates the per-route check to the injected Authorizer.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, perm string) bool {
	if err := s.authz.Authorize(r.Context(), perm); err != nil {
		respond.Err(w, r, err)
		return false
	}
	return true
}

func (s *Server) KpGen(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:kp_gen") {
		return
	}
	var req dto.KpGenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.KpGen(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) GenSign(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:gen_sign") {
		return
	}
	var req dto.SignReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.GenSign(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) Ecdh(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:ecdh") {
		return
	}
	var req dto.EcdhReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.Ecdh(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) ExpKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:exp_key") {
		return
	}
	var req dto.ExpKeyReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.ExpKey(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) ExpTr31(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:exp_tr31") {
		return
	}
	var req dto.ExpTr31Req
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.ExpTr31(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) RandGen(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:rand_gen") {
		return
	}
	var req dto.RandGenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.RandGen(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) ExpTr34(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:exp_tr34") {
		return
	}
	var req dto.ExpTr34Req
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.ExpTr34(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) KeyGen(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:key_gen") {
		return
	}
	var req dto.KeyGenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.KeyGen(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) KcvGen(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:kcv_gen") {
		return
	}
	var req dto.KcvGenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.KcvGen(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) IpekDerive(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:ipek_derive") {
		return
	}
	var req dto.IpekDeriveReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.IpekDerive(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) DataEncr(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:data_encr") {
		return
	}
	var req dto.DataEncrReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.DataEncr(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) DataDecr(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:data_decr") {
		return
	}
	var req dto.DataDecrReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.DataDecr(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) Mac(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:mac") {
		return
	}
	var req dto.MacReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.Mac(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) TransPin(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:trans_pin") {
		return
	}
	var req dto.TransPinReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.TransPin(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) Wrap(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:wrap") {
		return
	}
	var req dto.WrapReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.Wrap(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) Unwrap(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "crypto:unwrap") {
		return
	}
	var req dto.UnwrapReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.crypto.Unwrap(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}