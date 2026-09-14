package authz

import (
	"context"
	"strings"

	"common/auth"
	"common/errs"
)

// rolePerms is the crypto service RBAC policy: role → permissions. Permissions
// are per-endpoint (`crypto:kp_gen`, `serv:cert:create`, ...); handlers check
// permissions, never role names.
var rolePerms = map[string][]string{
	"admin": {
		"crypto:*",
		"serv:*",
	},
	"operator": {
		"crypto:gen_sign",
		"crypto:key_gen",
		"crypto:kcv_gen",
		"crypto:data_encr",
		"crypto:data_decr",
		"crypto:mac",
		"crypto:rand_gen",
	},
	"reader": {
		"crypto:rand_gen",
	},
	"key_custodian": {
		"internal:unwrap",
	},
}

// Can reports whether any of the user's roles grants the permission.
// "crypto:*" matches every action on the resource.
func Can(perm string, roles []string) bool {
	for _, role := range roles {
		for _, p := range rolePerms[role] {
			if p == perm {
				return true
			}
			if strings.HasSuffix(p, ":*") && strings.HasPrefix(perm, strings.TrimSuffix(p, "*")) {
				return true
			}
		}
	}
	return false
}

// Policy is the production Authorizer: 401 without an authenticated
// UserContext, 403 when the user's roles lack the permission.
type Policy struct{}

func (Policy) Authorize(ctx context.Context, perm string) error {
	uc, ok := auth.UserFromContext(ctx)
	if !ok {
		return errs.UnAuth{Msg: "authentication required"}
	}
	if !Can(perm, uc.Roles) {
		return errs.Forbidden{Msg: "forbidden"}
	}
	return nil
}

// PermitAll opens every registered endpoint in explicitly insecure local mode.
type PermitAll struct{}

func (PermitAll) Authorize(context.Context, string) error { return nil }
