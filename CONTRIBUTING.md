# Contributing

Thanks for your interest in contributing to **bulletproof-governance-plugin**.

## Getting Started

1. Fork the repository and create a feature branch from `main`.
2. Follow the setup steps in [docs/INSTALL.md](docs/INSTALL.md) (or the README)
   to get a working local environment.
3. Make your changes in small, focused commits.

## Before You Open a Pull Request

- **Run the test suite** and make sure it passes.
- **Add tests** for any new behavior or bug fix.
- **Keep changes surgical** — unrelated refactoring makes review harder.
- **Update documentation** (README / docs/) when behavior or configuration
  changes.
- Do not commit secrets, tokens, or machine-specific paths. Configuration
  belongs in environment variables with portable defaults.

## Pull Request Process

1. Describe **what** the change does and **why**.
2. Link any related issue.
3. CI must pass before review.
4. A maintainer will review; expect requests for changes — that's normal.

## Reporting Bugs

Open a GitHub issue with reproduction steps, expected vs. actual behavior, and
environment details. For security vulnerabilities, **do not open a public
issue** — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
repository's [Apache-2.0 license](LICENSE).
