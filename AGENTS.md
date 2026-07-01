# AGENTS.md -- PySafeguard

Python SDK for the One Identity Safeguard Web API. Published on
[PyPI](https://pypi.org/project/pysafeguard/). Requires Python >= 3.10.

Core deps: `requests`, `truststore`, and `typing_extensions` on Python < 3.11.
Optional extras: `async` (aiohttp) and `signalr` (signalrcore).

## Project structure

```
PySafeguard/
|-- src/pysafeguard/    # SDK package: clients, auth, errors, A2A, events, HiddenString
|-- tests/              # Unit tests
|   `-- integration/    # Live-appliance integration tests
|-- samples/            # Auth, A2A, and SignalR examples
|-- pipeline-templates/ # Shared Azure Pipelines templates
|-- pyproject.toml      # Poetry metadata and pytest config
|-- ruff.toml           # Ruff config
|-- mypy.ini            # Mypy config
`-- azure-pipelines.yml # CI/CD entrypoint
```

## Setup and build

```bash
pip install poetry
poetry install --all-extras
poetry build
```

## Linting

```bash
poetry run ruff check src/
poetry run ruff format --check src/
poetry run mypy src/
```

All code must pass `mypy --strict`. Ruff enforces 160-character lines.

## Testing

```bash
poetry run python -m pytest tests/ -m "not integration"
poetry run python -m pytest tests/ -m integration
```

`pytest-asyncio` uses `asyncio_mode = "auto"`. Integration tests auto-skip when
`SPP_HOST` is unset. The Device Code interactive integration test additionally
requires `SPP_DEVICE_CODE_INTERACTIVE=1` (it waits for a human to approve the
login in a browser) and stays skipped otherwise. For non-trivial auth, API, A2A,
or event changes, ask for appliance access. See the `testing-guide` skill for
fixtures and env vars.

## Code conventions

- Keep type annotations complete and `mypy --strict` clean.
- Use PascalCase for classes and snake_case for methods and attributes.
- Use reStructuredText docstrings.
- Keep constructors side-effect free.
- Use auth strategy objects, keyword-only args after the first positional
  parameters, no mutable defaults, explicit `json` / `data`, intentional
  `__all__`, and `HiddenString` for secrets.

## CI/CD

See the `build-and-release` skill for pipeline details, version derivation,
and publishing workflow.

## Security

- Never commit passwords, tokens, A2A API keys, private keys, generated test
  certs, `.pypirc`, or service-connection output.
- Wrap new secret-bearing fields in `HiddenString` immediately so `repr()` and
  `str()` stay redacted.
- Use `HiddenString.value` only where plaintext is required; avoid logging it
  and treat `get_value()` as deprecated compatibility.
- Prefer CA bundle verification over `verify=False`; use
  `REQUESTS_CA_BUNDLE` / `WEBSOCKET_CLIENT_CA_BUNDLE` when needed.

## Versioning

`pyproject.toml` holds the base semantic version. CI stamps tagged releases and
`.devN` prereleases via `versionnumber.ps1`; details live in the
`build-and-release` skill.

## On-demand skills

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Tests, fixtures, live appliance setup | `.agents/skills/testing-guide/SKILL.md` |
| API Patterns | HTTP methods, streaming, errors, token lifecycle | `.agents/skills/api-patterns/SKILL.md` |
| Architecture | Module internals, PKCE, HiddenString, SignalR internals | `.agents/skills/architecture/SKILL.md` |
| Build and Release | Azure Pipelines, tags, releases, PyPI publish | `.agents/skills/build-and-release/SKILL.md` |
| A2A Workflow | Certificate registration, API keys, A2A retrieval, brokering, listeners | `.agents/skills/a2a-workflow/SKILL.md` |

## Deprecations (v8.0)

- `Services` -> `Service`, `HttpMethods` -> `HttpMethod`, `A2ATypes` -> `A2AType`, `SshKeyFormats` -> `SshKeyFormat`
- `HiddenString.get_value()` -> use `.value`

## Keeping this file current

When a change affects setup, linting, testing, security, versioning, pipeline
behavior, or skill routing, update this file and the relevant
`.agents/skills/*/SKILL.md` in the same change.
