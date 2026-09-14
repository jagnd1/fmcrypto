# Setup — prerequisites, config, build, run

## Prerequisites

- Go 1.27+ (repo is a `go.work` workspace over `services/common` + `services/crypto_svc`)
- Docker + Docker Compose (optional, for the container image)
- gRPC tooling (only when regenerating the proto): `protoc`, `protoc-gen-go`,
  `protoc-gen-go-grpc`
  ```bash
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
  go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
  ```

## Config (.env)

`docker-compose.yml` (repo root) reads environment via `${VAR:-default}`
interpolation. Copy `.env.example` to `.env` and adjust:

```bash
cp services/crypto_svc/.env.example .env
```

Key vars: `APP_ENV`, `PORT`, `GRPC_PORT`, `CRYPTO_HSM` (`GP` software, future
`PS`/`AT` real HSMs), `SOFTWARE_LMK`, and the API-key auth block
(`API_KEY_PREFIX`, `API_KEYS`, `API_KEY_ROLES`).

**Auth** — startup requires `API_KEYS` (sha256 hex hashes) unless the explicit
`ALLOW_INSECURE_AUTH=true` local-development override is set. The override is
rejected in production and applies consistently to REST and gRPC. Generate a
hash with:

```bash
printf '%s' "<plaintext-key>" | shasum -a 256 | cut -d' ' -f1
```

GP is a deterministic development/test emulator and is rejected when
`APP_ENV=production`. A production deployment must select a hardware provider
after its adapter is implemented. gRPC reflection is disabled unless
`GRPC_REFLECTION=true`. The internal clear-key `unwrap` command is separately
controlled by `ENABLE_INTERNAL_UNWRAP` and the `key_custodian` role.

## Build

```bash
cd services/crypto_svc
make build          # go build -o crypto .
make vet            # go vet ./...
```

## Run

Local dev:

```bash
cd services/crypto_svc
make run            # = go run .
```

Container:

```bash
docker compose up --build   # from repo root; REST :8001, gRPC :50051
```

Health: `GET /healthz` (liveness, open) and `GET /readyz` (readiness, open),
plus a legacy `GET /health` probe kept for drop-in compatibility.

## Regenerate layers

```bash
make proto          # protoc → gen/crypto/v1 (after proto/crypto/v1 changes)
```

## Directory

See the layout tree in `services/crypto_svc/README.md`.
