# Contributing

Secret Scanner CLI is a defensive security project for authorized repository
auditing. Contributions should keep that scope clear and should not add
credential theft, token exfiltration, exploit logic, bypasses, or unauthorized
access behavior.

## Development Workflow

Use short-lived branches from `develop`:

- `feature/...` for new functionality.
- `fix/...` for bug fixes.
- `test/...` for test-only work.
- `docs/...` for documentation.
- `refactor/...` for internal changes without behavior changes.
- `chore/...` for tooling and maintenance.

Do not work directly on `main`. `main` is reserved for stable releases.

## Commit Style

Use Conventional Commits:

```text
type(scope): description
```

Examples:

```text
feat(cli): add scan org command
fix(github): handle rate limit retries
test(scanner): cover partial organization failures
docs(readme): document authorized usage
ci: add coverage reporting
```

Keep commits atomic. Avoid mixing unrelated code, tests, documentation, and
tooling changes unless they are part of the same logical unit.

## Local Checks

Run these before opening a pull request:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy src tests
python -m pytest
```

Coverage is enforced in CI with `pytest-cov`.

## Pull Request Checklist

- [ ] Code is formatted.
- [ ] Lint passes.
- [ ] Static typing passes.
- [ ] Tests are added or updated.
- [ ] Tests pass locally.
- [ ] No tokens or secrets are logged.
- [ ] Tests do not perform real GitHub API calls.
- [ ] Documentation is updated when behavior changes.
- [ ] Commits are atomic and use Conventional Commits.

## Release Process

Releases are tag-triggered. Pushing a tag matching `v*.*.*` runs
[.github/workflows/release.yml](.github/workflows/release.yml), which builds
the sdist/wheel, publishes to PyPI via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no API
token stored in this repo), and creates a GitHub release with the built
artifacts attached.

To cut a release:

1. On `develop`, bump `version` in [pyproject.toml](pyproject.toml) and move
   the relevant [CHANGELOG.md](CHANGELOG.md) `[Unreleased]` entries under a
   new `[X.Y.Z] - YYYY-MM-DD` heading.
2. Merge that into `main`.
3. Tag the resulting commit on `main` as `vX.Y.Z` and push the tag.

The workflow refuses to publish if the tag doesn't match the version in
`pyproject.toml`. Before the first release, a maintainer must register this
repository as a Trusted Publisher for the `secret-scanner-cli` PyPI project
(PyPI supports doing this before the project's first upload via a pending
publisher) and create a `pypi` environment in this repository's settings for
the publish job to target.

## Security Expectations

- Never print or store full secret values.
- Keep detected values redacted in output and reports.
- Do not commit `.env` files or real credentials.
- Use mocks or fakes for tests that involve GitHub behavior.
- Keep all GitHub HTTP access centralized in `github_client.py`.
