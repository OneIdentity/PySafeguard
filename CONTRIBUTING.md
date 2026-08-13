# Contributing to PySafeguard

Thanks for your interest in improving PySafeguard, the Python SDK for the
One Identity Safeguard Web API.

## Reporting issues

- **Bugs and feature requests:** open a GitHub Issue.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Prerequisites

- [Python 3.10](https://www.python.org/downloads/) or later.
- [Poetry](https://python-poetry.org/docs/#installation).
- (Optional) access to a Safeguard for Privileged Passwords appliance to
  run the integration tests.

## Building

    pip install poetry
    poetry install --all-extras
    poetry build

## Testing

Hermetic unit tests require no appliance:

    poetry run python -m pytest tests/ -m "not integration"

Integration tests **skip automatically** when `SPP_HOST` is unset. To run
them against a lab appliance, set `SPP_HOST` (plus `SPP_USERNAME` /
`SPP_PASSWORD`):

    poetry run python -m pytest tests/ -m integration

## Coding conventions

    poetry run ruff check src/
    poetry run ruff format --check src/
    poetry run mypy src/

Code must be `mypy --strict` clean. See [AGENTS.md](AGENTS.md) for the full
conventions.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Keep commits focused with clear messages.
3. Ensure `ruff check src/`, `ruff format --check src/`, `mypy src/`, and
   `pytest tests/ -m "not integration"` pass.
4. Open a pull request describing the behavior you changed and the tests
   that prove it.