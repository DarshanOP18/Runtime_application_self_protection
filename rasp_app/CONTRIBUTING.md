# Contributing

Thank you for improving the Runtime Application and Self Protection SDK.

## Development Expectations

- Keep security-related changes explicit and well documented.
- Prefer small, reviewable pull requests.
- Use conventional commits for all changes.
- Do not commit secrets, API keys, or private certificates.
- Preserve existing security checks unless a change is intentionally replacing them.

## Local Setup

```bash
flutter pub get
flutter analyze
flutter test
```

For release validation:

```bash
flutter build apk --release
```

## Pull Request Checklist

- Include a short summary of the security or UX impact.
- Mention any new API, platform channel, or schema change.
- Update docs when behavior changes.
- Add screenshots for UI updates.
- Call out migration impact if you changed public methods or response shapes.

## Commit Convention

Use Conventional Commits:

- `feat:` new capability
- `fix:` bug fix
- `perf:` performance improvement
- `docs:` documentation only
- `refactor:` internal restructuring
- `security:` protection or hardening change

Example:

```text
feat(rasp): add Frida, VPN, and device fingerprint checks
```

## Security Reporting

If you discover a security issue, do not open a public issue with exploit details.
Describe the impact, affected platforms, and recommended remediation instead.

## Documentation Ownership

When behavior changes:

- Update `README.md`
- Update `CHANGELOG.md`
- Update the relevant docs in `docs/`
- Update any code comments or API docs that are now stale
