// Package grpcserver adapts the usecase layer to gRPC. Machine clients
// authenticate with an API key only (strict); no JWT auth on gRPC.
package grpcserver

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"strings"

	"common/auth"
	"common/errs"

	"cryptosvc/gen/crypto/v1"
	"cryptosvc/internal/authz"
	"cryptosvc/internal/dto"
	"cryptosvc/internal/services"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// RecoverInterceptor contains panics from gRPC handlers — the analog of the
// HTTP Recover middleware. Chained outermost.
func RecoverInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if p := recover(); p != nil {
				slog.ErrorContext(ctx, "panic", "panic", p, "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// APIKeyInterceptor authenticates machine clients with an API key and stores
// the UserContext in the context. Strict: an API key is mandatory.
func APIKeyInterceptor(v auth.APIKeyVerifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		key := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if vals := md.Get("authorization"); len(vals) > 0 {
				key = strings.TrimPrefix(vals[0], "Bearer ")
			}
		}
		if key == "" {
			return nil, status.Error(codes.Unauthenticated, "api key required")
		}
		uc, err := v.ValidateAPIKey(ctx, key)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid api key")
		}
		return handler(auth.WithUserContext(ctx, uc), req)
	}
}

// InsecureDevelopmentInterceptor is used only when the explicit local
// development override is active. It supplies the same admin identity that the
// REST PermitAll authorizer represents; internal commands remain unavailable.
func InsecureDevelopmentInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		uc := auth.UserContext{Subject: "insecure-development", Roles: []string{"admin"}}
		return handler(auth.WithUserContext(ctx, uc), req)
	}
}

// CryptoServer is a thin transport adapter over the same usecase layer.
type CryptoServer struct {
	cryptov1.UnimplementedCryptoServiceServer
	crypto         *services.Crypto
	serv           *services.Server
	internalUnwrap bool
}

func New(crypto *services.Crypto, serv *services.Server, internalUnwrap bool) *CryptoServer {
	return &CryptoServer{crypto: crypto, serv: serv, internalUnwrap: internalUnwrap}
}

func (s *CryptoServer) KpGen(ctx context.Context, req *cryptov1.KpGenRequest) (*cryptov1.KpGenResponse, error) {
	if err := authorize(ctx, "crypto:kp_gen"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.KpGen(ctx, dto.KpGenReq{Algo: req.Algo, UseMode: req.UseMode})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.KpGenResponse{Status: resp.Status, Pk: resp.Pk, SkLmk: resp.SkLmk}, nil
}

func (s *CryptoServer) GenSign(ctx context.Context, req *cryptov1.GenSignRequest) (*cryptov1.GenSignResponse, error) {
	if err := authorize(ctx, "crypto:gen_sign"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.GenSign(ctx, dto.SignReq{Msg: req.Msg, SkLmk: req.SkLmk, Algo: req.Algo})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.GenSignResponse{Status: resp.Status, Signature: resp.Signature}, nil
}

func (s *CryptoServer) Ecdh(ctx context.Context, req *cryptov1.EcdhRequest) (*cryptov1.EcdhResponse, error) {
	if err := authorize(ctx, "crypto:ecdh"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.Ecdh(ctx, dto.EcdhReq{EphPk: req.EphPk, Algo: req.Algo, KeyType: req.KeyType, UseMode: req.UseMode, SharedInfo: req.SharedInfo})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.EcdhResponse{Status: resp.Status, DerivedKey: resp.DerivedKey, Kcv: resp.Kcv, RecpEphPk: resp.RecpEphPk}, nil
}

func (s *CryptoServer) ExpKey(ctx context.Context, req *cryptov1.ExpKeyRequest) (*cryptov1.ExpKeyResponse, error) {
	if err := authorize(ctx, "crypto:exp_key"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.ExpKey(ctx, dto.ExpKeyReq{KeyLmk: req.KeyLmk, Kcv: req.Kcv, Pk: req.Pk})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.ExpKeyResponse{Status: resp.Status, KeyPk: resp.KeyPk}, nil
}

func (s *CryptoServer) ExpTr31(ctx context.Context, req *cryptov1.ExpTr31Request) (*cryptov1.ExpTr31Response, error) {
	if err := authorize(ctx, "crypto:exp_tr31"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.ExpTr31(ctx, dto.ExpTr31Req{KeyLmk: req.KeyLmk, ZmkLmk: req.ZmkLmk, Iksn: req.Iksn})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.ExpTr31Response{Status: resp.Status, KeyZmk: resp.KeyZmk}, nil
}

func (s *CryptoServer) RandGen(ctx context.Context, req *cryptov1.RandGenRequest) (*cryptov1.RandGenResponse, error) {
	if err := authorize(ctx, "crypto:rand_gen"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.RandGen(ctx, dto.RandGenReq{Len: req.Len})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.RandGenResponse{Status: resp.Status, RandNo: resp.RandNo}, nil
}

func (s *CryptoServer) ExpTr34(ctx context.Context, req *cryptov1.ExpTr34Request) (*cryptov1.ExpTr34Response, error) {
	if err := authorize(ctx, "crypto:exp_tr34"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.ExpTr34(ctx, dto.ExpTr34Req{Kbpk: req.Kbpk, Kcv: req.Kcv, KdhCert: req.KdhCert, KrdCert: req.KrdCert, KdhSkLmk: req.KdhSkLmk})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.ExpTr34Response{Status: resp.Status, Aa: resp.Aa, Ed: resp.Ed, Signature: resp.Signature}, nil
}

func (s *CryptoServer) KeyGen(ctx context.Context, req *cryptov1.KeyGenRequest) (*cryptov1.KeyGenResponse, error) {
	if err := authorize(ctx, "crypto:key_gen"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.KeyGen(ctx, dto.KeyGenReq{KeyType: req.KeyType, UseMode: req.UseMode, Algo: req.Algo, ExpKey: req.ExpKey})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.KeyGenResponse{Status: resp.Status, KeyLmk: resp.KeyLmk, Kcv: resp.Kcv}, nil
}

func (s *CryptoServer) KcvGen(ctx context.Context, req *cryptov1.KcvGenRequest) (*cryptov1.KcvGenResponse, error) {
	if err := authorize(ctx, "crypto:kcv_gen"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.KcvGen(ctx, dto.KcvGenReq{KeyLmk: req.KeyLmk})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.KcvGenResponse{Status: resp.Status, Kcv: resp.Kcv}, nil
}

func (s *CryptoServer) IpekDerive(ctx context.Context, req *cryptov1.IpekDeriveRequest) (*cryptov1.IpekDeriveResponse, error) {
	if err := authorize(ctx, "crypto:ipek_derive"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.IpekDerive(ctx, dto.IpekDeriveReq{BdkLmk: req.BdkLmk, Iksn: req.Iksn, Tk: req.Tk, Algo: req.Algo, UseMode: req.UseMode})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.IpekDeriveResponse{Status: resp.Status, IpekLmk: resp.IpekLmk, IpekTk: resp.IpekTk, Kcv: resp.Kcv}, nil
}

func (s *CryptoServer) DataEncr(ctx context.Context, req *cryptov1.DataEncrRequest) (*cryptov1.DataEncrResponse, error) {
	if err := authorize(ctx, "crypto:data_encr"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.DataEncr(ctx, dto.DataEncrReq{KeyLmk: req.KeyLmk, Ksn: req.Ksn, Iv: req.Iv, EncrMode: req.EncrMode, Msg: req.Msg, Algo: req.Algo})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.DataEncrResponse{Status: resp.Status, EncrMsg: resp.EncrMsg}, nil
}

func (s *CryptoServer) DataDecr(ctx context.Context, req *cryptov1.DataDecrRequest) (*cryptov1.DataDecrResponse, error) {
	if err := authorize(ctx, "crypto:data_decr"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.DataDecr(ctx, dto.DataDecrReq{KeyLmk: req.KeyLmk, Ksn: req.Ksn, Iv: req.Iv, EncrMode: req.EncrMode, EncrMsg: req.EncrMsg, Algo: req.Algo})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.DataDecrResponse{Status: resp.Status, Msg: resp.Msg}, nil
}

func (s *CryptoServer) Mac(ctx context.Context, req *cryptov1.MacRequest) (*cryptov1.MacResponse, error) {
	if err := authorize(ctx, "crypto:mac"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.Mac(ctx, dto.MacReq{KeyLmk: req.KeyLmk, Ksn: req.Ksn, MacMode: req.MacMode, Msg: req.Msg, Mac: req.Mac})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.MacResponse{Status: resp.Status, MacResp: resp.MacResp}, nil
}

func (s *CryptoServer) TransPin(ctx context.Context, req *cryptov1.TransPinRequest) (*cryptov1.TransPinResponse, error) {
	if err := authorize(ctx, "crypto:trans_pin"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.TransPin(ctx, dto.TransPinReq{KeyLmk: req.KeyLmk, Ksn: req.Ksn, SrcPinblk: req.SrcPinblk, DestKey: req.DestKey, DestKsn: req.DestKsn, Pan: req.Pan})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.TransPinResponse{Status: resp.Status, DestPinblk: resp.DestPinblk}, nil
}

func (s *CryptoServer) Wrap(ctx context.Context, req *cryptov1.WrapRequest) (*cryptov1.WrapResponse, error) {
	if err := authorize(ctx, "crypto:wrap"); err != nil {
		return nil, err
	}
	resp, err := s.crypto.Wrap(ctx, dto.WrapReq{Algo: req.Algo, Header: req.Header, Kbpk: req.Kbpk, Key: req.Key})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.WrapResponse{Status: resp.Status, KeyKbpk: resp.KeyKbpk}, nil
}

func (s *CryptoServer) Unwrap(ctx context.Context, req *cryptov1.UnwrapRequest) (*cryptov1.UnwrapResponse, error) {
	if !s.internalUnwrap {
		return nil, status.Error(codes.Unimplemented, "operation is disabled")
	}
	if err := authorize(ctx, "internal:unwrap"); err != nil {
		return nil, err
	}
	slog.InfoContext(ctx, "internal crypto command", "operation", "unwrap", "phase", "start")
	resp, err := s.crypto.Unwrap(ctx, dto.UnwrapReq{KeyKbpk: req.KeyKbpk, Kbpk: req.Kbpk})
	if err != nil {
		slog.WarnContext(ctx, "internal crypto command", "operation", "unwrap", "phase", "failed")
		return nil, grpcErr(err)
	}
	slog.InfoContext(ctx, "internal crypto command", "operation", "unwrap", "phase", "complete")
	return &cryptov1.UnwrapResponse{Status: resp.Status, Key: resp.Key}, nil
}

func (s *CryptoServer) CertCreate(ctx context.Context, req *cryptov1.CertCreateRequest) (*cryptov1.CertResponse, error) {
	if err := authorize(ctx, "serv:cert:create"); err != nil {
		return nil, err
	}
	resp, err := s.serv.CertCreate(ctx, dto.CertCreateReq{Csr: req.Csr, IssuerCert: req.IssuerCert, SkLmk: req.SkLmk, CertLevel: req.CertLevel, Algo: req.Algo})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.CertResponse{Status: resp.Status, Cert: resp.Cert}, nil
}

func (s *CryptoServer) CertRenew(ctx context.Context, req *cryptov1.CertUpdateRequest) (*cryptov1.CertResponse, error) {
	if err := authorize(ctx, "serv:cert:update"); err != nil {
		return nil, err
	}
	resp, err := s.serv.CertRenew(ctx, dto.CertUpdateReq{Cert: req.Cert, IssuerCert: req.IssuerCert, SkLmk: req.SkLmk, CertLevel: req.CertLevel, Algo: req.Algo})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.CertResponse{Status: resp.Status, Cert: resp.Cert}, nil
}

func (s *CryptoServer) CrlMgmt(ctx context.Context, req *cryptov1.CrlMgmtRequest) (*cryptov1.CrlMgmtResponse, error) {
	if err := authorize(ctx, "serv:crl"); err != nil {
		return nil, err
	}
	resp, err := s.serv.CrlMgmt(ctx, dto.CrlMgmtReq{Cert: req.Cert, IssuerCert: req.IssuerCert, SkLmk: req.SkLmk, Algo: req.Algo, Crl: req.Crl})
	if err != nil {
		return nil, grpcErr(err)
	}
	return &cryptov1.CrlMgmtResponse{Status: resp.Status, Crl: resp.Crl}, nil
}

func authorize(ctx context.Context, perm string) error {
	uc, ok := auth.UserFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	if !authz.Can(perm, uc.Roles) {
		return status.Error(codes.PermissionDenied, "forbidden")
	}
	return nil
}

// grpcErr maps the common/errs taxonomy to gRPC codes (mirrors respond.Err).
func grpcErr(err error) error {
	var (
		inv errs.Invalid
		nf  errs.NotFound
		cf  errs.Conflict
		un  errs.UnAuth
		fb  errs.Forbidden
		big errs.TooLarge
		ni  errs.NotImplemented
		ci  interface {
			error
			InvalidMessage() string
		}
	)
	switch {
	case errors.As(err, &inv):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &ci):
		return status.Error(codes.InvalidArgument, ci.InvalidMessage())
	case errors.As(err, &nf):
		return status.Error(codes.NotFound, "not found")
	case errors.As(err, &cf):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.As(err, &un):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.As(err, &fb):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.As(err, &big):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.As(err, &ni):
		return status.Error(codes.Unimplemented, err.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
