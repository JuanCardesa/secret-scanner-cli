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

## Security Expectations

- Never print or store full secret values.
- Keep detected values redacted in output and reports.
- Do not commit `.env` files or real credentials.
- Use mocks or fakes for tests that involve GitHub behavior.
- Keep all GitHub HTTP access centralized in `github_client.py`.
