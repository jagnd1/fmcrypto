# Deployment Guide

This guide covers deployment options and security configurations for the fmcrypto Service.

## Quick Start

### Development
```bash
cd deployment
./run_dev.sh
```

### Production
```bash
cd deployment
./run_prod.sh
```

## Docker Images

### Available Images
- `python:3.13-slim` - Standard Debian-based image (~121 MB)
- `python:3.13-alpine` - Alpine-based image (~56.5 MB)
- `distroless/python3` - Google distroless image (~50-60 MB)

## Configuration

### Environment Variables
- `HSM_IP` - HSM server IP address
- `HSM_PORT` - HSM server port (default: 1234)
- `CRYPTO_HSM` - HSM type (default: GP)
- `ENVIRONMENT` - Environment setting

### Docker Compose
- Development: `docker-compose.yml`
- Production: `docker-compose.prod.yml`
