package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"common/logging"
	"common/middleware"

	"cryptosvc/gen/crypto/v1"
	"cryptosvc/internal/apikey"
	"cryptosvc/internal/authz"
	"cryptosvc/internal/config"
	"cryptosvc/internal/crypto"
	"cryptosvc/internal/grpcserver"
	"cryptosvc/internal/handlers"
	"cryptosvc/internal/health"
	"cryptosvc/internal/hsm"
	svcmw "cryptosvc/internal/middleware"
	"cryptosvc/internal/routers"
	"cryptosvc/internal/services"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load(os.Args[1:], os.LookupEnv)
	if err != nil {
		slog.ErrorContext(ctx, "config", "err", err)
		os.Exit(1)
	}
	logging.Setup(slog.LevelInfo)

	// HSM provider — a single seam over symmetric-key and PKI operations. GP is
// the software implementation; real HSMs (PS/AT) plug in here unchanged.
	var h hsm.HSM
	switch cfg.HSMType {
	case "", "GP":
		lmk := crypto.Lmk(nil)
		if cfg.SoftwareLMK != "" {
			b, err := hex.DecodeString(cfg.SoftwareLMK)
			if err != nil {
				slog.ErrorContext(ctx, "software lmk", "err", err)
				os.Exit(1)
			}
			lmk = b
		}
		h = hsm.NewGP(lmk)
	default:
		slog.ErrorContext(ctx, "unsupported hsm", "hsm", cfg.HSMType)
		os.Exit(1)
	}
	cryptoSvc := services.NewCrypto(h)
	serverSvc := services.NewServer(h)

	apiKeyRoles := cfg.APIKeyRoles
	if len(apiKeyRoles) == 0 {
		apiKeyRoles = []string{"admin"}
	}
	apiKeyVerifier := apikey.NewVerifier(cfg.APIKeyPrefix, cfg.APIKeys, apiKeyRoles)

	authEnabled := cfg.AuthEnabled()
	var authorizer handlers.Authorizer = authz.PermitAll{}
	if authEnabled {
		authorizer = authz.Policy{}
	}

	root := http.NewServeMux()
	health.Register(root) // public probes bypass auth

	apiMux := http.NewServeMux()
	routers.Register(apiMux, handlers.New(cryptoSvc, serverSvc, authorizer))

	apiMws := []func(http.Handler) http.Handler{}
	if authEnabled {
		// REST requires an API key when keys are configured; otherwise open.
		apiMws = append(apiMws, svcmw.APIKeyAuth(apiKeyVerifier))
	}
	apiMws = append(apiMws, middleware.MaxBodyBytes(1<<20), middleware.Timeout(5*time.Second))

	root.Handle("/", middleware.Chain(apiMux, apiMws...))

	handler := middleware.Chain(root,
		middleware.SecurityHeaders,
		middleware.Recover,
		middleware.RequestID,
		middleware.AccessLog,
	)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		slog.InfoContext(ctx, "listening", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, "serve", "err", err)
			os.Exit(1)
		}
	}()

	// gRPC transport: machine clients authenticate with an API key (strict).
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		grpcserver.RecoverInterceptor(), // outermost: panics never kill the server
		grpcserver.APIKeyInterceptor(apiKeyVerifier),
	))
	cryptov1.RegisterCryptoServiceServer(grpcServer, grpcserver.New(cryptoSvc, serverSvc))
	reflection.Register(grpcServer) // service discovery for grpcurl/dev tools
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		slog.ErrorContext(ctx, "grpc listen", "err", err)
		os.Exit(1)
	}
	go func() {
		slog.InfoContext(ctx, "grpc listening", "port", cfg.GRPCPort)
		if err := grpcServer.Serve(grpcLis); err != nil {
			slog.ErrorContext(ctx, "grpc serve", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.InfoContext(ctx, "shutting down")
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	grpcServer.GracefulStop()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.ErrorContext(ctx, "shutdown", "err", err)
		os.Exit(1)
	}
}