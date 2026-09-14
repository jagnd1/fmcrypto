# TODO

This file records the hardening and migration-parity work found while reviewing
fmcrypto against the current `jagnd1/crud` Go service reference and the earlier
Python/FastAPI crypto service. Items are ordered by deployment risk. Completing
the endpoint list alone does not establish behavioral or security parity.

## P0: production safety

- [ ] **Fail closed when authentication is missing.** REST currently becomes
      public when `API_KEYS` is empty. Require authentication by default and
      permit open REST only behind an explicit local-development flag. Apply
      the same environment policy to REST and gRPC. Keep reflection off unless
      explicitly enabled for development.
- [ ] **Remove the implicit software LMK.** The GP provider must not derive a
      key from the known string `lmk`. Require `SOFTWARE_LMK` when the GP
      provider is selected, mark GP as development/test-only, and prevent a
      production environment from starting with it.
- [ ] **Constrain and validate cryptographic inputs before provider calls.** Add
      an upper bound to random generation and validate KSN, IKSN, key-block,
      key length, PIN block, algorithm and mode fields before slicing or
      allocating. Malformed client input must return InvalidArgument/4xx rather
      than panic or become an opaque 500.
- [ ] **Reject unsupported parameters.** GP currently accepts but ignores or
      hardcodes parts of key type/use mode, encryption mode, KSN handling, MAC
      mode and PIN-translation source/destination schemes. Implement each
      advertised combination or return a typed not-supported/invalid error.
- [ ] **Resolve the clear-key API boundary.** `Unwrap` returns clear key bytes,
      contradicting the documented claim that keys never leave the engine in
      clear form. Remove it from production, or isolate it as an explicitly
      enabled, strongly authorized administrative operation with audit records.
- [ ] **Map provider validation errors consistently.** Convert
      `crypto.ErrInvalid` and provider-specific failures into the common error
      taxonomy so REST and gRPC produce stable client, dependency and internal
      error classes.

## P1: service baseline

- [ ] Port the `crud` fail-fast configuration behavior: reject malformed
      integer, duration and boolean environment variables and partial security
      configuration.
- [ ] Add `ReadHeaderTimeout`, inbound gRPC message-size limits, opt-in gRPC
      reflection and a deadline-bounded graceful shutdown that falls back to a
      forced stop.
- [ ] Define deployment TLS ownership. Use ingress termination by default;
      support native TLS/mTLS when the HSM deployment requires end-to-end
      client identity.
- [ ] Make HSM calls context-aware and check cancellation/deadlines around
      expensive software operations. A real HSM adapter must receive the
      request context.
- [ ] Replace unconditional readiness with provider-aware readiness, including
      connectivity/session checks for hardware HSM adapters.
- [ ] Add CI with pinned tools and gates for format, vet, staticcheck,
      govulncheck, race tests, standalone modules, protobuf regeneration,
      container build and vulnerability scanning.
- [ ] Correct `docs/testing.md`: the 19 handlers are implemented and no longer
      return scaffolded 501 responses. Document actual known-answer, REST and
      gRPC coverage.
- [ ] Add gRPC transport tests, production-auth configuration tests, startup
      composition tests, and explicit tests for every P0 invalid-input case.

## P1: Python-to-Go migration parity

- [ ] Add a checked-in capability matrix with one status for every Python
      endpoint and adapter operation: `ported`, `intentionally dropped`,
      `deferred`, or `unsupported`.
- [ ] Record and decide the payShield capabilities present in the Python
      adapter but not exposed by its router: ARQC verification and ARPC
      generation, CVV/CVC generation and verification, PVV/PIN operations,
      PIN offset operations, TR-31 import and RSA PIN translation.
- [ ] Compare request normalization, response encoding, error behavior and
      cryptographic outputs against the Python service using shared golden
      vectors. Include negative and boundary vectors, not only happy paths.
- [ ] Implement the production payShield/AT adapters or explicitly declare the
      Go service development-only until a hardware-backed provider is present.
- [ ] Run the Python and Go services in shadow comparison for supported
      operations before switching existing issuance or acquiring consumers.

## Shared-code maintenance

- [ ] Record the exact `jagnd1/crud` commit from which `services/common` was
      derived and maintain a review ledger for later security fixes.
- [ ] Keep this repository independently buildable. Because fmcrypto is public,
      it must not depend on a private common module. If stable primitives are
      later published as a versioned module, adopt them through semantic
      releases and compatibility tests rather than an unversioned copy.
