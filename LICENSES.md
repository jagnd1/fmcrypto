# Third-Party Licenses

This document lists third-party components and their licensing information for
the Go port of the fmcrypto crypto service (`services/crypto_svc`).

## Project License

fmcrypto Service is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Go Dependencies

The runtime is **stdlib-first**: the only third-party runtime dependencies are
the gRPC transport stack.

| Package | Purpose | License |
|---------|---------|---------|
| google.golang.org/grpc | gRPC transport | Apache-2.0 |
| google.golang.org/protobuf | protobuf runtime | BSD-3-Clause |
| golang.org/x/{net,sys,text,sync} | transitive stdlib-adjacent | BSD-3-Clause |
| google.golang.org/genproto/googleapis/rpc | transitive gRPC helpers | Apache-2.0 |

No crypto, HTTP, or framework dependencies are used.

## Go Standard Library

The Go standard library (`net/http`, `crypto/*`, `encoding/asn1`, `log/slog`,
`context`) is licensed under the **BSD-3-Clause** Go license
(https://go.dev/LICENSE).

## Framework Provenance

`services/common` (auth, errs, respond, middleware, cache, config, logging,
reqctx, httpx, ids, validate) and the layered architecture are derived from the
[crud](https://github.com/jagnd1/crud) Go service skeleton. crud carries no
separate license file; it is incorporated here under the project's MIT license.

## Third-Party Source Code / Standards

### ANSI X9.24-3-2017 AES DUKPT Reference Implementation

The DUKPT implementation in `services/crypto_svc/internal/crypto/dukpt` is
based on the reference implementation provided by the Accredited Standards
Committee X9 (ASC X9) for ANSI X9.24-3-2017.

- **Source**: https://x9.org/standards/x9-24-part-3-test-vectors/
- **Standard**: ANSI X9.24-3-2017 Supplement Python Source Code
- **License**: Open source (no warranty, as-is)
- **Original Disclaimer**: "The included source code contains no warranty or guarantees and is considered open source."

This code has been modified from the original X9 reference implementation to
integrate with the fmcrypto Service architecture and requirements.

## License Compatibility

All third-party components are compatible with the MIT license:
- MIT License: Compatible with MIT
- BSD-3-Clause: Compatible with MIT
- Apache-2.0: Compatible with MIT