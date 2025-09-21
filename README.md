# fmcrypto service

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=jagnd1_fmcrypto&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=jagnd1_fmcrypto)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jagnd1_fmcrypto&metric=coverage)](https://sonarcloud.io/summary/new_code?id=jagnd1_fmcrypto)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=jagnd1_fmcrypto&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=jagnd1_fmcrypto)

a cryptographic and pki service built with FastAPI for secure key management, encryption, and certificate operations.

## overview

fmcrypto service provides two main services:

- **crypto service** : key generation, encryption, digital signatures, mac operations, pin translation, and key wrapping
- **pki service** : certificate generation, renewal, csr processing, and crl management

## quick start

### development
```bash
cd deployment
./run_dev.sh
```

### production
```bash
cd deployment
./run_prod.sh
```

### testing
```bash
cd testing
./run_tests.sh
```

## requirements

- python 3.13+
- docker and docker compose
- pytest and pytest-cov

## env variables

- `HSM_IP` - hsm server ip address
- `HSM_PORT` - hsm server port (default: 1234)
- `CRYPTO_HSM` - hsm type (default: GP)
- `ENVIRONMENT` - env setting


## 3rd-party components

the aes dukpt implementation in `common/utils/sw/dukpt.py` is based on the reference implementation provided by the Accredited Standards Committee X9 (ASC X9) for ANSI X9.24-3-2017.

for complete licensing information, see [LICENSES.md](LICENSES.md).

## license

this project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
<!-- SonarCloud integration test - Sun Sep 21 10:30:04 IST 2025 -->
