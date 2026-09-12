package routers

import (
	"net/http"

	"common/middleware"

	"cryptosvc/internal/handlers"
)

// Register wires all crypto-service REST routes onto the given mux.
// Auth is applied at the outer middleware layer (see main.go); each route
// carries a resource:action permission checked by handlers.Server.authorize.
func Register(mux *http.ServeMux, s *handlers.Server) {
	register := func(pattern string, hf http.HandlerFunc) {
		mux.Handle(pattern, middleware.RoutePattern(pattern)(hf))
	}

	// /v1/crypto/*
	register("POST /v1/crypto/kp_gen", s.KpGen)
	register("POST /v1/crypto/gen_sign", s.GenSign)
	register("POST /v1/crypto/ecdh", s.Ecdh)
	register("POST /v1/crypto/exp_key", s.ExpKey)
	register("POST /v1/crypto/exp_tr31", s.ExpTr31)
	register("POST /v1/crypto/rand_gen", s.RandGen)
	register("POST /v1/crypto/exp_tr34", s.ExpTr34)
	register("POST /v1/crypto/key_gen", s.KeyGen)
	register("POST /v1/crypto/kcv_gen", s.KcvGen)
	register("POST /v1/crypto/ipek_derive", s.IpekDerive)
	register("POST /v1/crypto/data_encr", s.DataEncr)
	register("POST /v1/crypto/data_decr", s.DataDecr)
	register("POST /v1/crypto/mac", s.Mac)
	register("POST /v1/crypto/trans_pin", s.TransPin)
	register("POST /v1/crypto/wrap", s.Wrap)
	register("POST /v1/crypto/unwrap", s.Unwrap)

	// /v1/serv/*
	register("POST /v1/serv/cert", s.CertCreate)
	register("PUT /v1/serv/cert", s.CertRenew)
	register("POST /v1/serv/crl", s.CrlMgmt)
}