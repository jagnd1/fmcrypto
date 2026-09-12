# fmcrypto

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=jagnd1_fmcrypto&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=jagnd1_fmcrypto)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jagnd1_fmcrypto&metric=coverage)](https://sonarcloud.io/summary/new_code?id=jagnd1_fmcrypto)

A cryptographic and PKI service for secure key management, encryption, and
certificate operations — **written in Go**, served over **REST and gRPC**.

## overview

- **crypto service**: key generation (AES/TDES/RSA/ECC), encryption/decryption,
  digital signatures, CMAC, PIN translation, key wrapping/export (TR-31/TR-34),
  IPEK derivation, ECDH, random generation
- **pki (merged)**: certificate creation/renewal and CRL management under `/v1/serv`
- Both exposed over **REST** (`/v1/crypto/*`, `/v1/serv/*`) and **gRPC**
  (`crypto.v1.CryptoService`)

## architecture

The service is written in Go on the `crud` service framework — lean and
stdlib-first:

```
services/
  common/       # shared stdlib-only framework (auth, errs, respond, middleware)
  crypto_svc/   # this service
    internal/
      handlers/     # REST transport
      routers/      # route registration
      grpcserver/   # gRPC transport (API-key auth)
      services/     # usecase layer
      hsm/          # HSM seam: GP (software) + future PS/AT (real HSMs)
      crypto/       # pure-Go crypto engine (stdlib crypto/*)
      dukpt/        # ANSI X9.24-3 DUKPT (subpackage)
      apikey/ authz/ dto/ config/ middleware/ health/
```

- **Stdlib-first**: `net/http`, `log/slog`, `crypto/*`, `encoding/asn1`. The only
  third-party runtime deps are `grpc` + `protobuf` (gRPC transport). No database,
  no web framework, no crypto libraries.
- **HSM abstraction**: all symmetric-key and PKI operations flow through the
  `hsm.HSM` interface. GP (software, LMK-wrapped TR-31 key blocks) is the default;
  a real customer HSM (PS/AT) plugs in at the composition root (`CRYPTO_HSM`)
  with no usecase changes.
- **Key hygiene**: keys never leave the engine clear — they are created and
  returned wrapped under the LMK, mirroring a real HSM.

## quick start

```bash
cd services/crypto_svc && make run    # REST :8001, gRPC :50051
docker compose up --build             # containerized, from repo root
```

Auth is opt-in: leave `ZITADEL_ISSUER`/`AUDIENCE` blank for open REST endpoints,
or enable dual-auth (JWT or API key) and gRPC API-key auth. See
[`services/crypto_svc/docs/setup.md`](services/crypto_svc/docs/setup.md).

## testing

```bash
cd services/crypto_svc && make test    # go test ./...
```

See [`services/crypto_svc/docs/testing.md`](services/crypto_svc/docs/testing.md).

## legacy python implementation

The repository previously shipped a Python/FastAPI implementation
(`crypto_service/`, `common/`, `testing/`, `deployment/`). The Go service is a
fresh rewrite on the `crud` framework honoring the same API contract; the Python
tree served as the behavioral reference and its known-answer vectors. It is
**scheduled for removal** (recoverable via the `v1.0.0-python` tag). All new
development targets the Go service.

## license

MIT — see [LICENSE](LICENSE) and [LICENSES.md](LICENSES.md) for third-party
notices (incl. the ASC X9 DUKPT attribution).