package config

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port              int
	GRPCPort          int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ZitadelIssuer     string
	Audience          string
	ZitadelClientID   string
	ZitadelClientSecret string
	APIKeyPrefix      string
	APIKeys           []string // sha256 hex hashes of accepted API keys (stateless)
	APIKeyRoles       []string // roles granted to API-key callers (default: admin)
	SoftwareLMK       string   // hex; empty → default sha256("lmk") software-HSM LMK
	HSMType           string   // HSM provider: GP (software), PS/AT (future real HSMs)
}

// AuthEnabled is true when OIDC is configured; REST then requires either a
// bearer JWT or an API key. gRPC always requires an API key.
func (c Config) AuthEnabled() bool {
	return c.ZitadelIssuer != "" && c.Audience != ""
}

func Load(args []string, lookup func(string) (string, bool)) (Config, error) {
	fs := flag.NewFlagSet("crypto", flag.ContinueOnError)

	port := fs.Int("port", envInt(lookup, "PORT", 8001), "listen port")
	grpcPort := fs.Int("grpc-port", envInt(lookup, "GRPC_PORT", 50051), "grpc listen port")
	read := fs.Duration("read-timeout", envDur(lookup, "READ_TIMEOUT", 5*time.Second), "max read time")
	write := fs.Duration("write-timeout", envDur(lookup, "WRITE_TIMEOUT", 10*time.Second), "max write time")
	idle := fs.Duration("idle-timeout", envDur(lookup, "IDLE_TIMEOUT", 60*time.Second), "max idle time")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if *port < 1 || *port > 65535 {
		return Config{}, fmt.Errorf("port must be 1-65535, got %d", *port)
	}
	if *grpcPort < 1 || *grpcPort > 65535 {
		return Config{}, fmt.Errorf("grpc port must be 1-65535, got %d", *grpcPort)
	}
	if *read <= 0 || *write <= 0 || *idle <= 0 {
		return Config{}, fmt.Errorf("timeouts must be positive durations")
	}

	return Config{
		Port:                *port,
		GRPCPort:            *grpcPort,
		ReadTimeout:         *read,
		WriteTimeout:        *write,
		IdleTimeout:         *idle,
		ZitadelIssuer:       envStr(lookup, "ZITADEL_ISSUER", ""),
		Audience:            envStr(lookup, "AUDIENCE", ""),
		ZitadelClientID:     envStr(lookup, "ZITADEL_CLIENT_ID", ""),
		ZitadelClientSecret: envStr(lookup, "ZITADEL_CLIENT_SECRET", ""),
		APIKeyPrefix:        envStr(lookup, "API_KEY_PREFIX", "crypto_"),
		APIKeys:             splitEnv(lookup, "API_KEYS"),
		APIKeyRoles:         splitEnv(lookup, "API_KEY_ROLES"),
		SoftwareLMK:         envStr(lookup, "SOFTWARE_LMK", ""),
		HSMType:             envStr(lookup, "CRYPTO_HSM", "GP"),
	}, nil
}

func splitEnv(lookup func(string) (string, bool), key string) []string {
	v, ok := lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envStr(lookup func(string) (string, bool), key, fallback string) string {
	if v, ok := lookup(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(lookup func(string) (string, bool), key string, fallback int) int {
	if v, ok := lookup(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envDur(lookup func(string) (string, bool), key string, fallback time.Duration) time.Duration {
	if v, ok := lookup(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}