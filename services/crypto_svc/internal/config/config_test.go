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

func validEnv(overrides map[string]string) map[string]string {
	env := map[string]string{"ALLOW_INSECURE_AUTH": "true"}
	for key, value := range overrides {
		env[key] = value
	}
	return env
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(nil, testLookup(validEnv(nil)))
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
	if !cfg.AllowInsecureAuth {
		t.Error("test setup should explicitly allow insecure auth")
	}
}

func TestEnvOverrides(t *testing.T) {
	cfg, err := Load(nil, testLookup(validEnv(map[string]string{
		"PORT":           "9999",
		"GRPC_PORT":      "50052",
		"API_KEY_PREFIX": "fmcrypto_",
		"API_KEYS":       "abc123, def456",
	})))
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
	cfg, err := Load([]string{"-port", "7777"}, testLookup(validEnv(map[string]string{"PORT": "9999"})))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Port != 7777 {
		t.Errorf("port = %d, want 7777 (flag beats env)", cfg.Port)
	}
}

func TestInvalidPort(t *testing.T) {
	if _, err := Load([]string{"-port", "0"}, testLookup(validEnv(nil))); err == nil {
		t.Fatal("want error for port 0")
	}
	if _, err := Load([]string{"-port", "70000"}, testLookup(validEnv(nil))); err == nil {
		t.Fatal("want error for port 70000")
	}
}

func TestBadDuration(t *testing.T) {
	if _, err := Load([]string{"-read-timeout", "abc"}, testLookup(validEnv(nil))); err == nil {
		t.Fatal("want error for malformed duration")
	}
	if _, err := Load([]string{"-read-timeout", "0s"}, testLookup(validEnv(nil))); err == nil {
		t.Fatal("want error for zero duration")
	}
}

func TestZeroValueEnv(t *testing.T) {
	// empty-string env must fall back to defaults, not become empty
	cfg, err := Load(nil, testLookup(validEnv(map[string]string{"API_KEYS": ""})))
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
	cfg, err := Load(nil, testLookup(validEnv(map[string]string{"API_KEY_ROLES": "admin,operator"})))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.APIKeyRoles) != 2 {
		t.Errorf("api key roles = %v", cfg.APIKeyRoles)
	}
}

func TestAuthenticationFailsClosed(t *testing.T) {
	if _, err := Load(nil, testLookup(nil)); err == nil {
		t.Fatal("want missing API_KEYS to fail")
	}
}

func TestProductionRejectsInsecureModes(t *testing.T) {
	for _, env := range []map[string]string{
		{"APP_ENV": "production", "API_KEYS": "hash", "CRYPTO_HSM": "GP"},
		{"APP_ENV": "production", "API_KEYS": "hash", "CRYPTO_HSM": "PS", "ALLOW_INSECURE_AUTH": "true"},
	} {
		if _, err := Load(nil, testLookup(env)); err == nil {
			t.Fatalf("want unsafe production config rejected: %v", env)
		}
	}
}

func TestProductionAcceptsHardwareHSM(t *testing.T) {
	cfg, err := Load(nil, testLookup(map[string]string{
		"APP_ENV":    "production",
		"CRYPTO_HSM": "PS",
		"API_KEYS":   "hash",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HSMType != "PS" || !cfg.AuthEnabled() {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestInternalUnwrapRequiresAuthentication(t *testing.T) {
	_, err := Load(nil, testLookup(map[string]string{
		"ALLOW_INSECURE_AUTH":    "true",
		"ENABLE_INTERNAL_UNWRAP": "true",
	}))
	if err == nil {
		t.Fatal("want internal unwrap without API keys rejected")
	}
}

func TestMalformedEnvironmentFails(t *testing.T) {
	for _, env := range []map[string]string{
		{"PORT": "abc"},
		{"READ_TIMEOUT": "soon"},
		{"GRPC_REFLECTION": "perhaps"},
	} {
		if _, err := Load(nil, testLookup(validEnv(env))); err == nil {
			t.Fatalf("want malformed environment rejected: %v", env)
		}
	}
}
