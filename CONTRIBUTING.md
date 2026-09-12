# Contributing to FM Crypto Service

Thank you for your interest in contributing to this project!

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion:
1. Check if the issue already exists
2. Open a new issue with a clear description
3. Include steps to reproduce (for bugs)

### Submitting Changes

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Test thoroughly (`make test`, `go vet ./...`)
5. Commit with clear messages
6. Push to your fork
7. Submit a Pull Request

## Pull Request Guidelines

- Describe what your PR does and why
- Reference any related issues
- Ensure code follows existing style
- Update documentation if needed
- Keep changes focused and atomic

## Code Standards

- **Go** — the service is written in Go; run `gofmt` before committing and keep
  it `go vet`-clean. Follow idiomatic Go (stdlib-first, no framework).
- **Architecture** — layering is `handlers → services (usecase) → HSM seam →
  crypto engine`; the usecase layer depends only on the `hsm.HSM` interface so
  a real HSM (PS/AT) can replace the software `GP` implementation without
  touching it. Keep the seam.
- **Crypto** — use the Go stdlib (`crypto/*`) and the existing hand-rolled
  primitives; do not add third-party crypto libraries. Retain the ASC X9 DUKPT
  attribution (see LICENSE/LICENSES.md).
- Add comments for complex logic
- Update README.md for new features
- Maintain compatibility with existing dependencies

## Security

- Never commit private keys or sensitive data
- Keys are always LMK-wrapped (TR-31 key blocks) — never store clear keys
- Follow secure coding practices for crypto operations
- Report security vulnerabilities privately

## License

By contributing, you agree that your contributions will be licensed under the same license as this project.

## Questions?

Open an issue for discussion before starting major changes.