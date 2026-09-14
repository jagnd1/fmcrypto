# Python-to-Go migration parity

This document is the migration ledger for the earlier Python/FastAPI crypto
service in `dms-be/crypto_service`. It records what must remain compatible,
what has deliberately changed, and which hardware-provider capabilities are
still deferred. The old repository should not be required to establish the
public endpoint inventory during future work.

The status terms used here are:

- **Ported**: the Go service exposes the operation over REST and gRPC and the GP
  software provider implements it.
- **Hardened difference**: the operation exists, but the Go service rejects an
  unsafe or previously ignored input instead of silently accepting it.
- **Deferred**: the API or adapter capability is known, but production-provider
  implementation or parity evidence is not complete.
- **Internal**: intentionally unavailable as an ordinary public crypto command.

## Public API inventory

The Python router exposed 16 crypto operations and three certificate/CRL
operations. All 19 have a corresponding Go contract. This is API-surface
parity, not yet production-provider parity: the current Go implementation has
only the GP software provider. PayShield and AT integrations remain deferred.

| Python operation | Go REST operation | Go API status | GP status | Production provider status | Notes |
| --- | --- | --- | --- | --- | --- |
| `kp_gen` | `POST /v1/crypto/kp_gen` | Ported | Ported | Deferred | RSA/EC key-pair generation. Golden-vector comparison remains open. |
| `gen_sign` | `POST /v1/crypto/gen_sign` | Ported | Ported | Deferred | Malformed hexadecimal and base64 data is rejected as client input. |
| `ecdh` | `POST /v1/crypto/ecdh` | Ported | Ported | Deferred | Shared-info and key-use semantics require an explicit compatibility decision. |
| `exp_key` | `POST /v1/crypto/exp_key` | Ported | Ported | Deferred | Key type and use-mode behavior still requires parity vectors. |
| `exp_tr31` | `POST /v1/crypto/exp_tr31` | Ported | Ported | Deferred | Short or malformed key blocks are rejected before header slicing. |
| `rand_gen` | `POST /v1/crypto/rand_gen` | Ported | Ported | Deferred | Go caps one request at 4096 bytes to prevent unbounded allocation. |
| `exp_tr34` | `POST /v1/crypto/exp_tr34` | Ported | Ported | Deferred | Requires shared positive and negative TR-34 vectors. |
| `key_gen` | `POST /v1/crypto/key_gen` | Ported | Ported | Deferred | Key type/use-mode validation remains incomplete. |
| `kcv_gen` | `POST /v1/crypto/kcv_gen` | Ported | Ported | Deferred | Output encoding must be compared with hardware providers. |
| `ipek_derive` | `POST /v1/crypto/ipek_derive` | Hardened difference | Ported | Deferred | IKSN must be eight bytes. GP rejects transport-key export because it does not implement that parameter. |
| `data_decr` | `POST /v1/crypto/data_decr` | Hardened difference | Ported | Deferred | Go honors the requested cipher mode instead of always selecting CBC with padding. |
| `data_encr` | `POST /v1/crypto/data_encr` | Hardened difference | Ported | Deferred | Go honors the requested cipher mode instead of always selecting CBC with padding. |
| `mac` | `POST /v1/crypto/mac` | Hardened difference | Partial | Deferred | GP supports generation only. Verification and KSN-based MAC requests are rejected rather than ignored. |
| `trans_pin` | `POST /v1/crypto/trans_pin` | Hardened difference | Partial | Deferred | KSN must be 12 bytes and the PIN block 16 bytes. Destination KSN is rejected because GP does not implement it. |
| `wrap` | `POST /v1/crypto/wrap` | Ported | Ported | Deferred | GP wrapping is for local development and test only. |
| `unwrap` | Conditional `POST /v1/crypto/unwrap` | Internal | Ported | Deferred | Disabled by default. Requires `ENABLE_INTERNAL_UNWRAP=true`, authentication and the `key_custodian` role. Clear key material is never written to audit logs. |
| certificate create | `POST /v1/serv/cert` | Ported | Ported | Deferred | Certificate behavior has Go service tests; cross-runtime vectors remain open. |
| certificate renew | `PUT /v1/serv/cert` | Ported | Ported | Deferred | Certificate behavior has Go service tests; cross-runtime vectors remain open. |
| CRL management | `POST /v1/serv/crl` | Ported | Ported | Deferred | Certificate behavior has Go service tests; cross-runtime vectors remain open. |

## Provider boundary

GP is a deterministic software HSM emulator for development and tests. Its
fixed LMK derivation is intentional because reproducible wrapped values are
useful in local tests. The Go service refuses to start with GP when
`APP_ENV=production`. A production PayShield or AT adapter must use the
device's native LMK, session and key-custody model; it must not inherit GP's
deterministic LMK behavior.

The earlier Python service had GP, PayShield (`PS`) and AT adapters. The Go
service currently has only GP. Therefore no operation should be described as
production-migration complete until at least one hardware adapter is ported,
tested against a device or vendor simulator, and observed in shadow traffic.

## PayShield capabilities outside the Python public API

The Python PayShield adapter contains the following implementations, but its
FastAPI router did not expose them. They are product-capability candidates, not
missing public-route parity. Each requires an explicit API, authorization,
audit and provider-support decision before being added to Go.

| Capability | Python PayShield module | Status in Go | Required decision |
| --- | --- | --- | --- |
| ARQC verification and ARPC generation | `adapter/ps/verif_arqc.py` | Deferred | Define EMV input model, key references, methods 1/2 and option A/B support. |
| CVV/CVC generation | `adapter/ps/cv_gen.py` | Deferred | Define permitted variants, PAN/expiry/service-code handling and PCI logging boundary. |
| CVV/CVC verification | `adapter/ps/cv_verif.py` | Deferred | Define stable result codes without leaking verification detail. |
| PVV generation | `adapter/ps/gen_pvv.py` | Deferred | Define PVKI/PVK reference model and issuer authorization policy. |
| PVV verification | `adapter/ps/verif_pvv.py` | Deferred | Define PIN-failure response and rate-limit ownership. |
| PIN generation | `adapter/ps/pin_gen.py` | Deferred | Decide whether this is an issuance-only internal API. |
| IBM PIN offset | `adapter/ps/pin_offset.py` | Deferred | Define decimalization table and validation-data ownership. |
| Visa PIN offset | `adapter/ps/pin_off_visa.py` | Deferred | Define scheme-specific contract and test vectors. |
| TR-31 import | `adapter/ps/imp_tr31.py` | Deferred | Keep as a key-custodian operation with dual-control deployment procedures. |
| RSA PIN translation | `adapter/ps/trans_pin_rsa.py` | Deferred | Define certificate/key reference, source format and PCI PIN controls. |

## Intentional compatibility changes

The Python GP adapter silently ignored several request fields or hardcoded a
different value. Repeating that behavior would make the API misleading and
would hide migration errors. The Go service therefore follows these rules:

- An advertised option is implemented or rejected with a typed client error.
- Malformed hexadecimal, base64, PAN, KSN, IKSN, PIN block and TR-31 inputs are
  rejected before any provider call.
- Requested data-encryption modes are honored. They are not silently replaced
  with CBC plus padding.
- Unsupported MAC verification, KSN-based MAC, destination-KSN PIN translation
  and IPEK transport-key export are rejected.
- Unwrap is retained as an internal command, disabled by default and separated
  from the broad crypto administrator permission.
- REST and gRPC authentication fail closed unless an explicit non-production
  development override is enabled.

These differences are migration safeguards. Consumers that depended on an
ignored Python parameter must correct the request or wait for that capability
to be implemented explicitly.

## Parity proof still required

Before switching an issuance or acquiring consumer, run both services with a
shared vector corpus and compare normalized results. The corpus must contain:

1. Known-answer vectors for every deterministic operation and algorithm/mode.
2. Structural assertions for randomized operations, including key type,
   length, encoding and successful round trips.
3. Boundary and malformed values for every field accepted by REST and gRPC.
4. Provider failures, timeouts and unavailable-session behavior.
5. REST status/error envelopes and gRPC status-code equivalence.
6. Output normalization checks for hex case, base64, absent fields and
   provider-specific metadata.
7. Shadow comparison using representative issuance and acquiring traffic with
   sensitive values redacted from logs and reports.

Random bytes, generated keys, signatures and certificates cannot be compared
by raw equality unless the algorithm is deterministic. Compare their
cryptographic properties or verify them using the corresponding public
operation.

## Migration completion criteria

The Python service can be retired for a consumer only when:

- every operation used by that consumer is marked supported for its selected
  production provider;
- shared positive, negative and boundary vectors pass;
- authentication, role mapping, TLS ownership and audit retention are agreed;
- provider readiness, timeout and recovery behavior has been exercised;
- shadow comparison shows no unexplained semantic differences; and
- rollback to the Python path has been tested for the migration window.

Until then, this repository is a complete Go API and GP development reference,
but not a declaration of PayShield or AT production parity.
