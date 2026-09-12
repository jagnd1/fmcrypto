# crypto service (Go)

A lean, stdlib-first crypto/PKI service written in Go on the `crud` service
framework (`services/common`). It serves the fmcrypto crypto/PKI API over
**REST and gRPC** in idiomatic Go.

## Principles

- **Stdlib-first**: `net/http`, `log/slog`, `context`, `crypto/*`. No web
  framework, no ORM, no crypto libraries.
- **Layered**: `handlers → services (usecase) → HSM seam → crypto engine`,
  interfaces defined where consumed, manual DI at the composition root.
- **HSM abstraction**: the usecase depends only on the `hsm.HSM` interface.
  `GP` (software, LMK-wrapped TR-31 key blocks) is the default provider; real
  HSMs (PS/AT) plug in at `main.go` (`CRYPTO_HSM`) with no usecase changes.
- **Lean**: no database (the service is stateless); the only third-party
  runtime deps are `grpc` + `protobuf` for the gRPC transport.
- **Secure**: typed error taxonomy (no internal leakage), panic containment,
  request-id-correlated JSON logs, security headers, body-size limits, per-route
  deadlines, RS256-only JWT/JWKS with stampede protection.

## Architecture

```
main.go (composition root)
  REST:   routers(Server) → handlers(CryptoService, ServerService, Authorizer)
  gRPC:   grpcserver + Recover/APIKey interceptors
          → services (usecase) → hsm.HSM → internal/crypto engine (stdlib crypto/*)
```

| Layer | Purpose |
|---|---|
| `internal/handlers` | REST transport: decode → authorize → usecase → respond |
| `internal/routers` | route registration (`POST /v1/crypto/kp_gen`, …) |
| `internal/grpcserver` | gRPC transport (API-key only) + interceptors |
| `internal/services` | usecase layer (transport-agnostic, depends on `hsm.HSM`) |
| `internal/hsm` | HSM seam — `HSM` interface + `GP` (software) implementation |
| `internal/crypto` | pure-Go engine: AES/TDES/CMAC, TR-31 vD, LMK, RSA/ECC, ECDH, TR-34 CMS, X.509 TBS/CRL |
| `internal/crypto/dukpt` | ANSI X9.24-3 AES DUKPT (subpackage) |
| `internal/apikey` | stateless API-key generate/hash/verify |
| `internal/authz` | RBAC policy (role → `resource:action` permissions) |
| `internal/dto` | request/response models |
| `internal/config` | env/flags → typed config |
| `internal/middleware` | service-local dual-auth (JWT or API key) |
| `internal/health` | public `/healthz`, `/readyz`, legacy `/health` |
| `services/common` | shared framework (auth, errs, respond, middleware, …) |

## Endpoints

REST (`/v1/crypto/*` and `/v1/serv/*`) and gRPC (`crypto.v1.CryptoService`)
expose the same 19 operations:

- Key management: `kp_gen`, `key_gen`, `kcv_gen`, `exp_key`, `exp_tr31`,
  `exp_tr34`, `wrap`, `unwrap`
- Crypto ops: `gen_sign`, `ecdh`, `rand_gen`, `data_encr`, `data_decr`, `mac`,
  `trans_pin`, `ipek_derive`
- PKI (`/v1/serv`): `cert` create (POST), `cert` renew (PUT), `crl` (POST)

## Auth

- **REST**: dual-mode — a bearer JWT (OIDC/JWKS or introspection) **or** an
  API key (`X-API-Key` or `Authorization: Bearer <crypto_…>`). Opt-in: with no
  `ZITADEL_ISSUER`/`AUDIENCE` configured, endpoints are open (`PermitAll`).
- **gRPC**: API key **only** (strict), via the `APIKeyInterceptor`.

API keys are stateless: sha256 hashes configured via `API_KEYS` (env). See
`.env.example` and `docs/`.

## Build & run

```bash
cd services/crypto_svc
make run              # go run .  (REST :8001, gRPC :50051)
make test             # go test ./...
make vet              # go vet ./...
docker compose up --build   # from repo root
```

Health: `GET /healthz` (liveness) and `GET /readyz` (readiness), both public.

## Status

Complete: crypto engine, all 19 REST + gRPC operations, HSM seam, dual/REST +
API-key/gRPC auth, RBAC, health probes, tests, and docs.

## Third-party credit

The DUKPT implementation in `internal/crypto/dukpt` is based on the reference
implementation provided by the Accredited Standards Committee X9 (ASC X9) for
ANSI X9.24-3-2017 — see [LICENSES.md](../../LICENSES.md).