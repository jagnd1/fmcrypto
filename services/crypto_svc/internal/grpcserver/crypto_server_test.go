package grpcserver

import (
	"context"
	"testing"

	"common/auth"

	cryptov1 "cryptosvc/gen/crypto/v1"
	"cryptosvc/internal/crypto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCErrMapsCryptoValidation(t *testing.T) {
	err := grpcErr(crypto.ErrInvalid{Msg: "bad key block"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want %v", got, codes.InvalidArgument)
	}
}

func TestUnwrapDisabled(t *testing.T) {
	s := &CryptoServer{}
	_, err := s.Unwrap(t.Context(), &cryptov1.UnwrapRequest{})
	if got := status.Code(err); got != codes.Unimplemented {
		t.Fatalf("code = %v, want %v", got, codes.Unimplemented)
	}
}

func TestInsecureDevelopmentInterceptorInjectsAdmin(t *testing.T) {
	interceptor := InsecureDevelopmentInterceptor()
	_, err := interceptor(t.Context(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		uc, ok := auth.UserFromContext(ctx)
		if !ok || uc.Subject != "insecure-development" || len(uc.Roles) != 1 || uc.Roles[0] != "admin" {
			t.Fatalf("unexpected development identity: %+v, present=%v", uc, ok)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
