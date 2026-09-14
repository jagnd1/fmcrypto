# Auth — headless service-to-service

The crypto service is a headless service (no browser clients, no IdP). Auth is
**API-key based** for both transports:

| Transport | Auth | When enforced |
|---|---|---|
| REST | API key (`X-API-Key: crypto_<hex>` or `Authorization: Bearer crypto_<hex>`) | required unless explicit local insecure mode is enabled |
| gRPC | API key (`authorization: Bearer crypto_<hex>` metadata) | same policy as REST |

Startup fails when `API_KEYS` is empty unless `ALLOW_INSECURE_AUTH=true` is
explicitly set. Production rejects that override. Local insecure mode supplies
an admin development identity consistently to both transports.

## API keys (stateless)

Keys are configured, not stored in a DB: `API_KEYS` holds comma-separated
sha256 hex digests. The prefix (`API_KEY_PREFIX`, default `crypto_`)
distinguishes keys in the bearer slot. `API_KEY_ROLES` (default `admin`) grants
the RBAC roles for key callers.

Issue a dev key:

```bash
KEY="crypto_$(openssl rand -hex 16)"
echo "$KEY"                                    # keep this
printf '%s' "$KEY" | shasum -a 256 | cut -d' ' -f1   # → API_KEYS
```

## RBAC

`internal/authz` maps roles → permissions. Handlers check permissions, never
role names. Wildcard `resource:*` matches all actions on a resource.

| Role | Permissions |
|---|---|
| `admin` | `crypto:*`, `serv:*` |
| `operator` | `crypto:gen_sign`, `crypto:key_gen`, `crypto:kcv_gen`, `crypto:data_encr`, `crypto:data_decr`, `crypto:mac`, `crypto:rand_gen` |
| `reader` | `crypto:rand_gen` |
| `key_custodian` | `internal:unwrap` |

`unwrap` is not covered by the `admin` role's `crypto:*` wildcard. Its REST
route is absent and its gRPC method is disabled unless
`ENABLE_INTERNAL_UNWRAP=true`. Enabling it also requires configured API keys.
Calls are audited by operation and outcome only; request and response material
is never included in those audit records.
