package config

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment          string
	Port                 int
	GRPCPort             int
	ReadTimeout          time.Duration
	ReadHeaderTimeout    time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	HSMType              string // HSM provider: GP (software), PS/AT (future real HSMs)
	SoftwareLMK          string // hex; empty uses GP's deterministic development LMK
	AllowInsecureAuth    bool
	GRPCReflection       bool
	EnableInternalUnwrap bool

	APIKeyPrefix string   // prefix for expected API keys (default crypto_)
	APIKeys      []string // sha256 hex hashes of accepted API keys (stateless)
	APIKeyRoles  []string // roles granted to API-key callers (default: admin)
}

// AuthEnabled reports whether API keys are configured.
func (c Config) AuthEnabled() bool { return len(c.APIKeys) > 0 }

func Load(args []string, lookup func(string) (string, bool)) (Config, error) {
	fs := flag.NewFlagSet("crypto", flag.ContinueOnError)

	portDefault, err := envInt(lookup, "PORT", 8001)
	if err != nil {
		return Config{}, err
	}
	grpcPortDefault, err := envInt(lookup, "GRPC_PORT", 50051)
	if err != nil {
		return Config{}, err
	}
	readDefault, err := envDur(lookup, "READ_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	readHeaderDefault, err := envDur(lookup, "READ_HEADER_TIMEOUT", 2*time.Second)
	if err != nil {
		return Config{}, err
	}
	writeDefault, err := envDur(lookup, "WRITE_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	idleDefault, err := envDur(lookup, "IDLE_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
	}
	allowInsecureAuth, err := envBool(lookup, "ALLOW_INSECURE_AUTH", false)
	if err != nil {
		return Config{}, err
	}
	grpcReflection, err := envBool(lookup, "GRPC_REFLECTION", false)
	if err != nil {
		return Config{}, err
	}
	enableInternalUnwrap, err := envBool(lookup, "ENABLE_INTERNAL_UNWRAP", false)
	if err != nil {
		return Config{}, err
	}

	port := fs.Int("port", portDefault, "listen port")
	grpcPort := fs.Int("grpc-port", grpcPortDefault, "grpc listen port")
	read := fs.Duration("read-timeout", readDefault, "max read time")
	readHeader := fs.Duration("read-header-timeout", readHeaderDefault, "max header read time")
	write := fs.Duration("write-timeout", writeDefault, "max write time")
	idle := fs.Duration("idle-timeout", idleDefault, "max idle time")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if *port < 1 || *port > 65535 {
		return Config{}, fmt.Errorf("port must be 1-65535, got %d", *port)
	}
	if *grpcPort < 1 || *grpcPort > 65535 {
		return Config{}, fmt.Errorf("grpc port must be 1-65535, got %d", *grpcPort)
	}
	if *read <= 0 || *readHeader <= 0 || *write <= 0 || *idle <= 0 {
		return Config{}, fmt.Errorf("timeouts must be positive durations")
	}
	environment := strings.ToLower(envStr(lookup, "APP_ENV", "development"))
	if environment != "development" && environment != "test" && environment != "production" {
		return Config{}, fmt.Errorf("APP_ENV must be development, test, or production")
	}
	hsmType := strings.ToUpper(envStr(lookup, "CRYPTO_HSM", "GP"))
	if environment == "production" && hsmType == "GP" {
		return Config{}, fmt.Errorf("GP is a development/test HSM and cannot run in production")
	}
	apiKeys := splitEnv(lookup, "API_KEYS")
	if len(apiKeys) == 0 && !allowInsecureAuth {
		return Config{}, fmt.Errorf("API_KEYS is required; set ALLOW_INSECURE_AUTH=true only for local development")
	}
	if environment == "production" && allowInsecureAuth {
		return Config{}, fmt.Errorf("ALLOW_INSECURE_AUTH cannot be enabled in production")
	}
	if enableInternalUnwrap && len(apiKeys) == 0 {
		return Config{}, fmt.Errorf("ENABLE_INTERNAL_UNWRAP requires authenticated API keys")
	}

	return Config{
		Environment:          environment,
		Port:                 *port,
		GRPCPort:             *grpcPort,
		ReadTimeout:          *read,
		ReadHeaderTimeout:    *readHeader,
		WriteTimeout:         *write,
		IdleTimeout:          *idle,
		HSMType:              hsmType,
		SoftwareLMK:          envStr(lookup, "SOFTWARE_LMK", ""),
		AllowInsecureAuth:    allowInsecureAuth,
		GRPCReflection:       grpcReflection,
		EnableInternalUnwrap: enableInternalUnwrap,
		APIKeyPrefix:         envStr(lookup, "API_KEY_PREFIX", "crypto_"),
		APIKeys:              apiKeys,
		APIKeyRoles:          splitEnv(lookup, "API_KEY_ROLES"),
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

func envInt(lookup func(string) (string, bool), key string, fallback int) (int, error) {
	if v, ok := lookup(key); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return n, nil
	}
	return fallback, nil
}

func envDur(lookup func(string) (string, bool), key string, fallback time.Duration) (time.Duration, error) {
	if v, ok := lookup(key); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("%s must be a duration: %w", key, err)
		}
		return d, nil
	}
	return fallback, nil
}

func envBool(lookup func(string) (string, bool), key string, fallback bool) (bool, error) {
	v, ok := lookup(key)
	if !ok {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return b, nil
}
