# TODO

This file records the hardening and migration-parity work found while reviewing
fmcrypto against the current `jagnd1/crud` Go service reference and the earlier
Python/FastAPI crypto service. Items are ordered by deployment risk. Completing
the endpoint list alone does not establish behavioral or security parity.

## P0: production safety

- [x] **Fail closed when authentication is missing.** REST previously became
      public when `API_KEYS` is empty. Require authentication by default and
      permit open REST only behind an explicit local-development flag. Apply
      the same environment policy to REST and gRPC. Keep reflection off unless
      explicitly enabled for development.
- [x] **Confine the fixed software LMK to development.** GP is intentionally a
      local/test HSM emulator and may retain its deterministic fallback for
      reproducible development. Mark it non-production and prevent a production
      environment from starting with GP; production PS/AT integrations retain
      their native LMK and key-custody model.
- [ ] **Constrain and validate cryptographic inputs before provider calls.** Add
      an upper bound to random generation and validate KSN, IKSN, key-block,
      key length, PIN block, algorithm and mode fields before slicing or
      allocating. Malformed client input must return InvalidArgument/4xx rather
      than panic or become an opaque 500.
      Completed: random allocation bound, fixed IKSN/KSN/PIN-block lengths,
      decimal PAN validation, TR-31 header-length guard, and negative transport
      tests. Remaining: operation-by-operation key length and enum validation.
- [ ] **Reject unsupported parameters.** GP currently accepts but ignores or
      hardcodes parts of key type/use mode, encryption mode, KSN handling, MAC
      mode and PIN-translation source/destination schemes. Implement each
      advertised combination or return a typed not-supported/invalid error.
      Completed: encryption mode is honored; unsupported MAC verification,
      KSN-based MAC, destination KSN and IPEK transport-key export are rejected.
      Remaining: key type/use-mode and ECDH shared-info semantics.
- [x] **Protect the internal clear-key command.** `Unwrap` is an internal
      administrative operation. Keep it disabled by default, place it outside
      the broad crypto-admin wildcard, require a dedicated role, and audit its
      invocation without recording request, response, key material or derived
      values.
- [x] **Map provider validation errors consistently.** Convert
      `crypto.ErrInvalid` and provider-specific failures into the common error
      taxonomy so REST and gRPC produce stable client, dependency and internal
      error classes.

## P1: service baseline

- [x] Port the `crud` fail-fast configuration behavior: reject malformed
      integer, duration and boolean environment variables and partial security
      configuration.
- [x] Add `ReadHeaderTimeout`, inbound gRPC message-size limits, opt-in gRPC
      reflection and a deadline-bounded graceful shutdown that falls back to a
      forced stop.
- [ ] Define deployment TLS ownership. Use ingress termination by default;
      support native TLS/mTLS when the HSM deployment requires end-to-end
      client identity.
- [ ] Make HSM calls context-aware and check cancellation/deadlines around
      expensive software operations. A real HSM adapter must receive the
      request context.
- [x] Replace unconditional readiness with provider-aware readiness, including
      connectivity/session checks for hardware HSM adapters.
- [ ] Add CI with pinned tools and gates for format, vet, staticcheck,
      govulncheck, race tests, standalone modules, protobuf regeneration,
      container build and vulnerability scanning. Everything except
      staticcheck is wired; `v0.7.0` cannot decode Go 1.27 export data, so that
      gate remains deferred until a compatible release is available.
- [x] Correct `docs/testing.md`: the handlers are implemented and no longer
      return scaffolded 501 responses. Document actual known-answer, REST and
      gRPC coverage.
- [ ] Add complete gRPC transport tests, startup
      composition tests, and explicit tests for every P0 invalid-input case.
      Initial gRPC error/auth tests and production configuration tests are in
      place; full RPC coverage and composition tests remain.

## P1: Python-to-Go migration parity

- [x] Add a checked-in capability matrix with one status for every Python
      endpoint and adapter operation: `ported`, `intentionally dropped`,
      `deferred`, or `unsupported`. See `docs/python-migration-parity.md`.
- [x] Record and decide the payShield capabilities present in the Python
      adapter but not exposed by its router: ARQC verification and ARPC
      generation, CVV/CVC generation and verification, PVV/PIN operations,
      PIN offset operations, TR-31 import and RSA PIN translation. They are
      recorded as deferred product capabilities, not missing public-route
      parity, in `docs/python-migration-parity.md`.
- [ ] Compare request normalization, response encoding, error behavior and
      cryptographic outputs against the Python service using shared golden
      vectors. Include negative and boundary vectors, not only happy paths.
- [ ] Implement the production payShield/AT adapters or explicitly declare the
      Go service development-only until a hardware-backed provider is present.
- [ ] Run the Python and Go services in shadow comparison for supported
      operations before switching existing issuance or acquiring consumers.

## Shared-code maintenance

- [x] Record the exact `jagnd1/crud` commit from which `services/common` was
      derived and maintain a review ledger for later security fixes.
      Baseline reviewed and selectively ported: `b25ad5acddcc63e68df9cc34c66901d10a3745f5`.
- [ ] Keep this repository independently buildable. Because fmcrypto is public,
      it must not depend on a private common module. If stable primitives are
      later published as a versioned module, adopt them through semantic
      releases and compatibility tests rather than an unversioned copy.
