# Auth — REST dual-mode, gRPC API-key

## REST dual-auth

When `ZITADEL_ISSUER` and `AUDIENCE` are set, every `/v1/*` route requires
**either** a bearer JWT **or** an API key:

| Presentation | How it's validated |
|---|---|
| `Authorization: Bearer <jwt>` | OIDC/JWKS RS256 verify (or introspection when `ZITADEL_CLIENT_ID`+`_SECRET` set) → Zitadel claims mapped to `UserContext` |
| `Authorization: Bearer crypto_<hex>` | prefix match → API-key hash verify |
| `X-API-Key: crypto_<hex>` | API-key hash verify |

Without credentials → 401. Roles lacking the route permission → 403. If the
Zitadel vars are blank, REST endpoints are **open** (`authz.PermitAll`), the
scaffold/test default.

## gRPC (API-key only)

gRPC never accepts JWT. The `APIKeyInterceptor` requires
`authorization: Bearer crypto_<hex>` metadata; verified against the same
stateless hash set.

## API keys (stateless)

Keys are configured, not stored in a DB: `API_KEYS` holds comma-separated
sha256 hex digests. Prefix (`API_KEY_PREFIX`, default `crypto_`) distinguishes
keys from JWTs in the bearer slot. `API_KEY_ROLES` (default `admin`) grants the
RBAC roles for key callers.

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