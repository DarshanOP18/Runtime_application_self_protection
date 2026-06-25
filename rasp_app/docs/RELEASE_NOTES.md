# Release Notes v2.0.0

## Summary

This release turns the repository into an enterprise-grade RASP reference SDK with stronger runtime checks, cleaner UI, secure session handling, RBAC, and a simplified AI assistant.

## Highlights

- Added Frida, VPN, MITM, repackaging, overlay, accessibility, clone, binding, and geo-risk checks.
- Added device fingerprinting and offline compliance monitoring.
- Added secure login, verification flow, and session restoration.
- Added audit logs and admin-oriented RBAC screens.
- Added a polished security center and consistent dark visual system.
- Simplified the bot so it only appears when tapped.

## Security Improvements

- Added screenshot restriction listener setup.
- Added Firestore threat telemetry with fail-safe error handling.
- Added stronger app integrity and runtime tamper signals.
- Added session expiration and token invalidation behavior.

## Performance Improvements

- Centralized security evaluation in `RaspService.runChecks()`.
- Reduced repeated UI prompts by removing the persistent bot greeting bubble.
- Reused repository and session lookups instead of scattering state logic across screens.

## Breaking Changes

- The startup flow now expects `RaspGate` before authentication.
- Security consumers should read the extended `RaspCheckResult`.
- The assistant UI no longer shows an always-visible greeting chip.

## Recommended Version

- `2.0.0`

## Upgrade Notes

1. Update any integrations that expect the old minimal RASP result.
2. Review MethodChannel implementations for the new native hooks.
3. Configure Firebase only if threat telemetry is desired.
4. Regenerate screenshots and release assets for the new UI.
