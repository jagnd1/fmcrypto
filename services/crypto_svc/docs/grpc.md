# gRPC — transport, auth, grpcurl

## Service

`crypto.v1.CryptoService` mirrors every REST endpoint:

- 16 crypto RPCs: `KpGen`, `GenSign`, `Ecdh`, `ExpKey`, `ExpTr31`, `RandGen`,
  `ExpTr34`, `KeyGen`, `KcvGen`, `IpekDerive`, `DataEncr`, `DataDecr`, `Mac`,
  `TransPin`, `Wrap`, `Unwrap`
- 3 PKI RPCs: `CertCreate`, `CertRenew`, `CrlMgmt`

Messages mirror the REST JSON models (same field names; wire is protobuf).

## Auth

Strict API key: each call must carry `authorization: Bearer crypto_<hex>`
metadata, validated by `APIKeyInterceptor` against the stateless hash set.
No JWT on gRPC.

## grpcurl

```bash
grpcurl -plaintext -H "authorization: Bearer crypto_<key>" \
  localhost:50051 crypto.v1.CryptoService/RandGen \
  -d '{"len": "12"}'
```

List services / reflect:

```bash
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe crypto.v1.CryptoService
```

## Error mapping

`internal/grpcserver.grpcErr` maps `common/errs` → gRPC codes
(InvalidArgument, NotFound, AlreadyExists, Unauthenticated, PermissionDenied,
ResourceExhausted, Unimplemented; unknown → opaque Internal). Panics are
contained by `RecoverInterceptor`.