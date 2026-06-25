# Migration Guide

## From the starter Flutter version to v2.0.0

This release moves the project from a placeholder Flutter app to a full enterprise RASP reference implementation.

### What changed

- Added a real authentication flow with secure sessions.
- Added RBAC roles, permissions, and audit logging.
- Added a full security center instead of a single flat dashboard page.
- Added expanded runtime threat checks and telemetry.
- Added an AI assistant UI for security guidance.
- Replaced the temporary starter README with enterprise documentation.

## Breaking Considerations

### 1. App launch now passes through `RaspGate`

If you previously launched directly into your first screen, update your startup flow to:

1. Run `RaspService.runChecks()`
2. Handle blocked or deceptive states
3. Continue to `AuthGate`

### 2. Security results are richer

`RaspCheckResult` now contains additional threat fields:

- Frida
- VPN
- MITM
- repackaging
- overlay abuse
- accessibility abuse
- device risk
- cloning
- binding
- geo risk
- offline compliance

Update any existing consumers that only expected root, emulator, tamper, or debug flags.

### 3. Bot behavior is now tap-driven

The assistant no longer shows a persistent highlighted greeting bubble.

If your integration depended on that UI, replace it with a tap-to-open action.

### 4. Threat reporting is optional

If you do not configure Firebase, `ThreatReporterService` will fail safely.

### 5. Versioning

Recommended version for this release: `2.0.0`

If you package builds, align your application version and release notes with this bump.

## Upgrade Checklist

- Replace placeholder startup logic with `RaspGate`
- Validate new `RaspCheckResult` fields
- Review native MethodChannel implementations
- Confirm screenshot restriction hooks on each platform
- Configure Firebase only if telemetry is required
- Update screenshots and release assets
- Re-run `flutter analyze` and `flutter test`

## Feature Comparison

See [docs/FEATURE_COMPARISON.md](FEATURE_COMPARISON.md) for a side-by-side table.
