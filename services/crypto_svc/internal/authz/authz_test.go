package authz

import "testing"

func TestCan(t *testing.T) {
	cases := []struct {
		perm  string
		roles []string
		want  bool
	}{
		{"crypto:kp_gen", []string{"admin"}, true},
		{"internal:unwrap", []string{"admin"}, false},
		{"internal:unwrap", []string{"key_custodian"}, true},
		{"serv:crl", []string{"admin"}, true},
		{"crypto:kp_gen", []string{"operator"}, false},
		{"crypto:data_encr", []string{"operator"}, true},
		{"crypto:rand_gen", []string{"reader"}, true},
		{"crypto:mac", []string{"reader"}, false},
		{"crypto:mac", []string{"nobody"}, false},
		{"crypto:mac", nil, false},
	}
	for _, c := range cases {
		if got := Can(c.perm, c.roles); got != c.want {
			t.Errorf("Can(%q, %v) = %v, want %v", c.perm, c.roles, got, c.want)
		}
	}
}

func TestPolicy(t *testing.T) {
	// No authenticated user → UnAuth (Policy requires context)
	// (Authorize returning an error is the expected scaffold behavior for an
	// empty context; this test pins the contract.)
	if err := (Policy{}).Authorize(t.Context(), "crypto:kp_gen"); err == nil {
		t.Fatal("want error without UserContext")
	}
	// PermitAll always passes
	if err := (PermitAll{}).Authorize(t.Context(), "anything"); err != nil {
		t.Fatalf("PermitAll: %v", err)
	}
}
