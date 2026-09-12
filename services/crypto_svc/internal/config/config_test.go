package config

import (
	"testing"
	"time"
)

func testLookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(nil, testLookup(map[string]string{}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Port != 8001 {
		t.Errorf("port = %d, want 8001", cfg.Port)
	}
	if cfg.GRPCPort != 50051 {
		t.Errorf("grpc port = %d, want 50051", cfg.GRPCPort)
	}
	if cfg.APIKeyPrefix != "crypto_" {
		t.Errorf("prefix = %q, want crypto_", cfg.APIKeyPrefix)
	}
	if cfg.AuthEnabled() {
		t.Error("auth should be disabled by default")
	}
}

func TestEnvOverrides(t *testing.T) {
	cfg, err := Load(nil, testLookup(map[string]string{
		"PORT":         "9999",
		"GRPC_PORT":    "50052",
		"API_KEY_PREFIX": "fmcrypto_",
		"API_KEYS":     "abc123, def456",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Port != 9999 {
		t.Errorf("port = %d, want 9999", cfg.Port)
	}
	if cfg.APIKeyPrefix != "fmcrypto_" {
		t.Errorf("prefix = %q", cfg.APIKeyPrefix)
	}
	if len(cfg.APIKeys) != 2 || cfg.APIKeys[0] != "abc123" || cfg.APIKeys[1] != "def456" {
		t.Errorf("api keys = %v", cfg.APIKeys)
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	cfg, err := Load([]string{"-port", "7777"}, testLookup(map[string]string{"PORT": "9999"}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Port != 7777 {
		t.Errorf("port = %d, want 7777 (flag beats env)", cfg.Port)
	}
}

func TestInvalidPort(t *testing.T) {
	if _, err := Load([]string{"-port", "0"}, testLookup(map[string]string{})); err == nil {
		t.Fatal("want error for port 0")
	}
	if _, err := Load([]string{"-port", "70000"}, testLookup(map[string]string{})); err == nil {
		t.Fatal("want error for port 70000")
	}
}

func TestBadDuration(t *testing.T) {
	if _, err := Load([]string{"-read-timeout", "abc"}, testLookup(map[string]string{})); err == nil {
		t.Fatal("want error for malformed duration")
	}
	if _, err := Load([]string{"-read-timeout", "0s"}, testLookup(map[string]string{})); err == nil {
		t.Fatal("want error for zero duration")
	}
}

func TestZeroValueEnv(t *testing.T) {
	// empty-string env must fall back to defaults, not become empty
	cfg, err := Load(nil, testLookup(map[string]string{"API_KEYS": ""}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.APIKeys) != 0 {
		t.Errorf("api keys = %v", cfg.APIKeys)
	}
	if cfg.ReadTimeout != 5*time.Second {
		t.Errorf("read timeout = %v", cfg.ReadTimeout)
	}
}

func TestAPIKeyRolesDefaultEmpty(t *testing.T) {
	cfg, err := Load(nil, testLookup(map[string]string{"API_KEY_ROLES": "admin,operator"}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.APIKeyRoles) != 2 {
		t.Errorf("api key roles = %v", cfg.APIKeyRoles)
	}
}