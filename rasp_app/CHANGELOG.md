# Changelog

All notable changes to this project are documented here.

## [2.0.0] - 2026-06-22

### Added
- RBAC login flow with secure sessions and automatic session resume.
- Role-aware dashboard with verification flow, admin tools, and audit log browsing.
- Expanded RASP checks for Frida, VPN, overlay abuse, accessibility abuse, cloning, binding, offline compliance, and repackaging.
- Device fingerprinting and hardware identity change detection.
- Threat reporting to Firestore.
- AI security assistant with tap-to-open interaction.
- Enterprise documentation set: installation, API reference, migration guide, architecture, and release notes.

### Changed
- Replaced the starter Flutter placeholder README with enterprise-grade SDK documentation.
- Refactored the app into a consistent dark security theme.
- Reworked the RASP security center into a cleaner, less noisy layout.
- Simplified bot presence so the assistant no longer shows an always-on highlighted greeting bubble.
- Added a cleaner theme and shared visual system across auth, dashboard, and security pages.

### Fixed
- Improved session validation and session token persistence.
- Improved role upgrade flow for verified users.
- Reduced UI inconsistency between security and RBAC pages.

### Security
- Added screenshot restriction support and iOS screenshot listener setup.
- Added stronger device integrity and runtime tamper signals.
- Added MITM/SSL interception detection and risk reporting.

### Removed
- The old floating greeting-style bot prompt on the dashboard.
- Placeholder starter README content.

## [1.0.0] - 2026-06-04
- Initial Flutter application scaffold and baseline security project.
