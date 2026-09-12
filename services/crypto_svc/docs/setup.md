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

Key vars: `PORT`, `GRPC_PORT`, `CRYPTO_HSM` (provider: `GP` software, future
`PS`/`AT` real HSMs), `SOFTWARE_LMK` (software-HSM master key), and the auth
block (`ZITADEL_ISSUER`, `AUDIENCE`, `ZITADEL_CLIENT_ID`,
`ZITADEL_CLIENT_SECRET`, `API_KEYS`).

**Auth is opt-in** — leave the Zitadel vars blank for open endpoints, or set
them to enable REST dual-auth (JWT or API key). gRPC always requires an API key
present in `API_KEYS` as a sha256 hex hash:

```bash
printf '%s' "<plaintext-key>" | shasum -a 256 | cut -d' ' -f1
```

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
plus a legacy `GET /health` kept for drop-in compatibility with the Python-era
probe.

## Regenerate layers

```bash
make proto          # protoc → gen/crypto/v1 (after proto/crypto/v1 changes)
```

## Directory

See the layout tree in `services/crypto_svc/README.md`.