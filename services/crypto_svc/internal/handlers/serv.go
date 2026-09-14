package handlers

import (
	"net/http"

	"common/httpx"
	"common/respond"

	"cryptosvc/internal/dto"
)

// CertCreate handles POST /v1/serv/cert.
func (s *Server) CertCreate(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "serv:cert:create") {
		return
	}
	var req dto.CertCreateReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.serv.CertCreate(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// CertRenew handles PUT /v1/serv/cert.
func (s *Server) CertRenew(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "serv:cert:update") {
		return
	}
	var req dto.CertUpdateReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.serv.CertRenew(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// CrlMgmt handles POST /v1/serv/crl.
func (s *Server) CrlMgmt(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "serv:crl") {
		return
	}
	var req dto.CrlMgmtReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		respond.Err(w, r, err)
		return
	}
	resp, err := s.serv.CrlMgmt(r.Context(), req)
	if err != nil {
		respond.Err(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
