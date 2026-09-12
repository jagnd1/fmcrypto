# Testing — commands, coverage, verify

## Commands

From `services/crypto_svc/`:

```bash
make test             # go test ./...
make vet              # go vet ./...
go test -race ./...   # race detector
```

Workspace-wide (both modules), from `services/`:

```bash
go test ./common/... ./crypto_svc/...
```

## What's covered

- **`internal/handlers`** — route registration for all 19 REST endpoints
  (scaffold 501), RBAC 401/403 via injected `UserContext` (no mocks).
- **`internal/authz`** — role→permission matrix incl. wildcards.
- **`internal/config`** — defaults, env overrides, flag precedence, invalid
  values.
- **`services/common`** — the shared framework's own suite: auth (synthetic
  RS256 JWTs + httptest discovery/JWKS/introspection), middleware, errs.

Crypto engine vector tests (known-answer tests ported from the Python
implementation) arrive with Phases 2-4.

## Manual verify (live)

```bash
# health (public)
curl -s localhost:8001/healthz    # {"status":"ok"}

# REST (scaffold → 501 until engine lands)
curl -s -X POST localhost:8001/v1/crypto/rand_gen -d '{"len":"12"}'

# gRPC (API key required)
grpcurl -plaintext -H "authorization: Bearer crypto_<key>" \
  localhost:50051 crypto.v1.CryptoService/RandGen
```

Full auth + API-key setup is in [`docs/auth.md`](auth.md).