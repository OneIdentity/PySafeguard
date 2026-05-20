---
name: build-and-release
description: Use when changing Azure Pipelines, reproducing CI locally, or validating PySafeguard version stamping and publishing.
---

# Build and release

Use this skill when you need to change `azure-pipelines.yml`, debug why a build or release ran, reproduce the pipeline locally, or understand how PySafeguard versions are stamped and published.

## 1. Pipeline architecture

### Files involved

| File | Role |
|---|---|
| `azure-pipelines.yml` | Top-level pipeline definition: triggers, job conditions, GitHub release, and PyPI publish steps |
| `pipeline-templates/global-variables.yml` | Computes `isTagBuild` from `Build.SourceBranch` |
| `pipeline-templates/build-steps.yml` | Shared install/lint/test/build/twine-check steps used by both jobs |
| `versionnumber.ps1` | Converts the base semantic version into the build/package version and release tag |
| `pyproject.toml` | Poetry metadata, base semantic version, package name, dependencies, and pytest config |

### Trigger model

The pipeline is intentionally narrow:

- Push CI runs on `main` and `release-*`
- Tag builds run on tags matching `v*`
- PR validation runs for pull requests targeting `main` and `release-*`
- Docs-only changes are excluded from CI and PR runs:
  - `**/*.md`
  - `LICENSE`
  - `docs/`
  - `.github/CODEOWNERS`

### Job layout

There are no explicit Azure DevOps stages; the pipeline uses two jobs with mutually exclusive conditions:

1. `PRValidation`
   - Runs only when `Build.Reason == PullRequest`
   - Uses `ubuntu-latest`
   - Imports `pipeline-templates/build-steps.yml`
   - Validates install, version stamping, linting, typing, unit tests, packaging, and `twine check`

2. `BuildAndPublish`
   - Runs for non-PR builds
   - Uses the same shared build template
   - Always creates a GitHub release for merge/tag builds
   - Uploads to PyPI only when the build was triggered from a tag

### Shared build sequence

Both jobs run the same steps from `pipeline-templates/build-steps.yml`:

1. Select Python `3.12` with `UsePythonVersion@0`
2. Upgrade `pip` and `wheel`
3. Install Poetry
4. Run `poetry install --all-extras`
5. Execute `versionnumber.ps1`
6. Run `poetry run ruff check src/`
7. Run `poetry run ruff format --check src/`
8. Run `poetry run mypy src/`
9. Run unit tests only: `poetry run python -m pytest tests/ -m "not integration" --tb=short -q`
10. Build the wheel and sdist with `poetry build`
11. Install Twine and validate the package with `twine check dist/*`
12. Copy `dist/*` into the artifact staging directory
13. Publish the staged files as Azure Pipeline artifact `drop`

The artifact publishing steps are guarded with `succeededOrFailed()`, so failed builds still expose `dist/*` when those files exist.

### Release-specific steps

`BuildAndPublish` adds two publishing paths after the shared build:

- **GitHub release** via `GitHubRelease@1`
  - Service connection: `PangaeaBuild-GitHub`
  - Repository: `OneIdentity/PySafeguard`
  - Assets: `$(Build.ArtifactStagingDirectory)/dist/*`
  - Changelog: `commitBased`, compared to `lastFullRelease`
  - `isPreRelease` is `true` for non-tag builds

- **PyPI publish** via Twine
  - Runs only when `Build.SourceBranch` starts with `refs/tags/`
  - Installs Twine, authenticates with `TwineAuthenticate@1`, then uploads `dist/*`

## 2. Version strategy

### Single source of truth

The base semantic version lives in `pyproject.toml` under `[project].version`.

`versionnumber.ps1` reads it with:

```powershell
poetry version --short
```

That means the checked-in value is the release baseline, not necessarily the exact artifact version produced in CI.

### Tag builds

Tag builds are release builds.

- `isTagBuild` comes from `startsWith(Build.SourceBranch, 'refs/tags/')`
- `versionnumber.ps1` validates the tag with `^v\d+\.\d+\.\d+`
- The package version is the tag with the leading `v` removed
  - `v8.1.0` -> `8.1.0`
- `ReleaseTag` is the original tag name

The regex only validates the `v<major>.<minor>.<patch>` prefix, so tags with an allowed suffix after that prefix still pass.

### Non-tag builds

Branch builds become development packages.

- `PackageVersion = <semantic-version>.dev<BuildId % 65534>`
- Example: base `8.0.2` and build id `70001` becomes `8.0.2.dev4467`
- `ReleaseTag = dev/v<PackageVersion>`

The modulo keeps the dev suffix inside the range accepted by Python packaging tools.

### Important implications

- CI mutates the version in-place with `poetry version <PackageVersion>`
- Do not manually edit the checked-in version just to mimic a CI dev build
- If you run `versionnumber.ps1` locally, expect `pyproject.toml` to change until you reset it
- Real releases are created by pushing a `v*` tag, not by editing files in the build output

## 3. Build commands

### Local CI reproduction

Run these from the repo root:

```bash
pip install poetry
poetry install --all-extras
poetry run ruff check src/
poetry run ruff format --check src/
poetry run mypy src/
poetry run python -m pytest tests/ -m "not integration" --tb=short -q
poetry build
pip install twine
twine check dist/*
```

### Matching the pipeline environment

- Prefer Python `3.12` locally when reproducing CI because the pipeline pins that interpreter
- `poetry install --all-extras` is important because the repo's checks depend on dev tools and optional extras being available
- CI does **not** run integration tests; those remain a separate live-appliance workflow

### Simulating version stamping locally

Use PowerShell from the repo root:

```powershell
pwsh .\versionnumber.ps1 -BuildId 12345 -TagName v8.0.2 -IsTagBuild $true
pwsh .\versionnumber.ps1 -BuildId 12345 -TagName main -IsTagBuild $false
```

After a dry run, revert `pyproject.toml` unless you intentionally changed the base semantic version.

## 4. Publishing targets

### Registries and release destinations

| Target | When it runs | What is published |
|---|---|---|
| Azure Pipeline artifact `drop` | Every build, even on failure when artifacts exist | `dist/*` |
| GitHub Releases | Every non-PR build | `dist/*` plus generated changelog |
| PyPI | Tagged builds only | `dist/*` via Twine |

### Pre-release behavior

- Branch builds publish GitHub prereleases tagged `dev/v<PackageVersion>`
- Tag builds publish full GitHub releases and push the same package version to PyPI

### Signing

There is currently **no package signing step** in the pipeline.

- No GPG signing
- No Sigstore step
- No trusted publishing exchange beyond the configured Twine service connection

If signing is added later, update this skill and `AGENTS.md` in the same change.

## 5. Service connections / secrets required

### Azure DevOps connections and injected variables

- `PangaeaBuild-GitHub` - required by `GitHubRelease@1`
- `pypiOneIdentity` - required by `TwineAuthenticate@1`
- `$(PYPIRC_PATH)` - generated by Twine authentication and consumed by `twine upload`
- Build variables used by the versioning flow:
  - `Build.SourceBranch`
  - `Build.SourceBranchName`
  - `Build.SourceVersion`
  - `Build.BuildId`

### Secret handling rules

- Do not commit `.pypirc`, PyPI tokens, GitHub tokens, or exported service-connection credentials
- Do not hardcode release credentials into scripts or `pyproject.toml`
- Keep release automation inside Azure DevOps service connections whenever possible

### Safe release checklist

1. Update the base semantic version in `pyproject.toml` only when intentionally changing the SDK version line
2. Validate the shared build steps locally before pushing release changes
3. Push to `main` or `release-*` to verify dev build behavior
4. Push a `vX.Y.Z` tag to trigger the real PyPI publish path
5. When pipeline behavior changes, review all of:
   - `azure-pipelines.yml`
   - `pipeline-templates/build-steps.yml`
   - `pipeline-templates/global-variables.yml`
   - `versionnumber.ps1`
   - `AGENTS.md`
   - this skill
