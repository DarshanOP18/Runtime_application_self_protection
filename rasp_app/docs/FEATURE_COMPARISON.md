# Feature Comparison

| Area | v1 Baseline | v2.0.0 |
| --- | --- | --- |
| App launch | Placeholder Flutter entry | Security gate + auth gate |
| Authentication | Minimal / placeholder | Secure session-based login |
| RBAC | Limited | Roles, permissions, upgrade flow, audit logs |
| Dashboard | Simple security page | Role-aware enterprise dashboard |
| Threat checks | Root, emulator, tamper, debug | Expanded runtime RASP suite |
| Frida detection | Not documented | Added |
| VPN detection | Not documented | Added |
| Proxy / MITM | Not documented | Added |
| Signature verification | Not documented | Added |
| Repackaging detection | Not documented | Added |
| Device fingerprinting | Not documented | Added |
| Screenshot protection | Basic / limited | Runtime enabling + listener |
| AI assistant | Not available | Floating live helper |
| Threat telemetry | Not available | Firestore reporting hook |
| Docs | Starter README | Enterprise docs set |

## New API Surface

- `RaspService.runChecks()`
- `DeviceFingerprintService.checkDeviceRisk()`
- `GeoFilterService.isHighRiskIp()`
- `SslPinningService.isMitmDetected()`
- `ThreatReporterService.reportThreat(String)`
- `ScreenshotRestriction.enableScreenshotRestriction()`
- `ScreenshotRestriction.setScreenshotDetectedCallback(...)`
- `UserRepository.verifyAndUpgradeUser(int)`
- `UserRepository.getAuditLogs(...)`

## Removed or Deprecated UI

- Always-visible highlighted bot greeting bubble
- Starter README boilerplate
- Flat starter dashboard styling
