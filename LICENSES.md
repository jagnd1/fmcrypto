# Third-Party Licenses

This document lists third-party components and their licensing information.

## Project License

fmcrypto Service is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Python Dependencies

All dependencies are compatible with the MIT license:

| Package | Version | License |
|---------|---------|---------|
| fastapi-slim | 0.116.1 | MIT |
| pydantic | 2.11.9 | MIT |
| uvicorn | 0.35.0 | BSD |
| httpx | 0.28.1 | BSD |
| cryptography | 45.0.7 | Apache 2.0 / BSD |
| pycryptodome | 3.23.0 | BSD |
| asn1crypto | 1.5.1 | MIT |
| psec | 1.3.0 | MIT |
| PyJWT | 2.10.1 | MIT |
| python-json-logger | 3.3.0 | BSD |
| click | 8.2.1 | BSD |
| certifi | 2025.8.3 | MPL-2.0 |

## License Compatibility

All dependencies are compatible with the MIT license:
- MIT License: Compatible with MIT
- BSD License: Compatible with MIT  
- Apache 2.0: Compatible with MIT
- MPL-2.0: Compatible with MIT

## Third-Party Source Code

### ANSI X9.24-3-2017 AES DUKPT Reference Implementation

The AES DUKPT implementation in `common/utils/sw/dukpt.py` is based on the reference implementation provided by the Accredited Standards Committee X9 (ASC X9) for ANSI X9.24-3-2017.

- **Source**: https://x9.org/standards/x9-24-part-3-test-vectors/
- **Standard**: ANSI X9.24-3-2017 Supplement Python Source Code  
- **License**: Open source (no warranty, as-is)
- **Original Disclaimer**: "The included source code contains no warranty or guarantees and is considered open source."

This code has been modified from the original X9 reference implementation to integrate with the fmcrypto Service architecture and requirements.

