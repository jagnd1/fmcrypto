# Testing — commands, coverage, verify

## Commands

From `services/crypto_svc/`:

```bash
make test             # go test ./...
make vet              # go vet ./...
make test-race        # race detector, uncached
make lint             # format, vet, govulncheck
make proto-check      # regenerate protobuf output and require a clean diff
make standalone       # prove both modules with GOWORK=off
```

Workspace-wide (both modules), from `services/`:

```bash
go test ./common/... ./crypto_svc/...
```

## What's covered

- **`internal/handlers`** — route registration and implemented REST operations,
  RBAC 401/403, internal-unwrap isolation, happy paths, and invalid-input 422
  behavior via an injected `UserContext`.
- **`internal/grpcserver`** — crypto validation error mapping, disabled internal
  unwrap, and the explicit insecure-development identity.
- **`internal/authz`** — role→permission matrix incl. wildcards.
- **`internal/config`** — fail-closed auth, production GP rejection, internal
  unwrap prerequisites, malformed env values, overrides and flag precedence.
- **`internal/health`** — liveness remains process-only while readiness follows
  the configured HSM provider.
- **`services/common`** — the shared framework's own suite: errs, middleware.

Crypto engine known-answer vector tests cover the key-block, symmetric,
DUKPT, and asymmetric primitives.

## Manual verify (live)

```bash
# health (public)
curl -s localhost:8001/healthz    # {"status":"ok"}

# REST (local insecure mode from .env.example)
curl -s -X POST localhost:8001/v1/crypto/rand_gen \
  -H 'Content-Type: application/json' -d '{"len":"12"}'

# gRPC (API key required outside explicit local insecure mode)
grpcurl -plaintext -H "authorization: Bearer crypto_<key>" \
  localhost:50051 crypto.v1.CryptoService/RandGen
```

Full auth + API-key setup is in [`auth.md`](auth.md).
