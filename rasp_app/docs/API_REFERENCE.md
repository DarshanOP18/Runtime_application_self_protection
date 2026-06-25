# API Reference

## RaspService

### `Future<RaspCheckResult> runChecks()`

Runs the full security pipeline:

- root / jailbreak detection
- emulator detection
- debug detection
- tamper checks
- screenshot restriction setup
- Frida / VPN / overlay / accessibility checks
- signature and repackaging checks
- device fingerprint evaluation
- MITM / SSL interception detection
- offline compliance and geo risk checks
- threat reporting

## RaspCheckResult

Primary fields:

- `isRooted`
- `isEmulator`
- `isDebugging`
- `isTampered`
- `isBlockingEnforced`
- `screenshotBlockingEnabled`
- `isFridaDetected`
- `isVpnActive`
- `isMitmDetected`
- `isRepackaged`
- `hasReverseEngineeringTools`
- `isOverlayDetected`
- `isAccessibilityAbused`
- `isDeviceRisk`
- `deviceRiskReason`
- `isCloneDetected`
- `isDeviceBindingFailed`
- `isHighRiskIp`
- `isOfflineExceeded`

Convenience getters:

- `isThreatDetected`
- `shouldBlockApp`
- `shouldShowDeception`
- `threatSummary`

## ScreenshotRestriction

### `Future<bool> enableScreenshotRestriction()`
Enables screenshot blocking or listener setup.

### `Future<bool> disableScreenshotRestriction()`
Disables screenshot protection.

### `Future<bool> isScreenshotBlockingActive()`
Returns the current protection state.

### `void setScreenshotDetectedCallback(Function callback)`
Registers a callback for screenshot detection events.

### `void resetListener()`
Clears listener state.

## DeviceFingerprintService

### `Future<DeviceFingerprintResult> checkDeviceRisk()`

Checks for:

- disabled screen lock
- enabled ADB debugging
- permissive SELinux
- sideloaded install source
- hardware identity change

## DeviceFingerprintResult

- `bool isRisk`
- `String reason`
- `List<String> failedChecks`

## GeoFilterService

### `Future<bool> isHighRiskIp()`
Checks for high-risk geographies and proxy-style IP indicators.

## SslPinningService

### `Future<bool> isMitmDetected()`
Returns `true` if native proxy checks or TLS interception checks indicate a likely MITM attack.

## ThreatReporterService

### `Future<void> reportThreat(String threatSummary)`
Attempts to send a threat summary to Firestore.

## UserRepository

Key methods:

- `registerUser(...)`
- `loginUser(String email, String password)`
- `logoutUser(String sessionToken)`
- `verifyAndUpgradeUser(int userId)`
- `getUserWithRole(int userId)`
- `getUserBySessionToken(String sessionToken)`
- `checkPermission(int userId, String permissionName)`
- `getAllPermissionsForUser(int userId)`
- `getRoleWithPermissions(int roleId)`
- `changeUserRole(int adminUserId, int targetUserId, int newRoleId)`
- `isSessionValid(String sessionToken)`
- `isEmailTaken(String email)`
- `isUsernameTaken(String username)`
- `getAuditLogs({int? userId, int limit})`
- `getAllUsers()`

## Models

### `UserModel`

Notable computed flags:

- `isNewUser`
- `isExistingUser`
- `isAdmin`
- `isModerator`

### `RoleModel`

Contains:

- `id`
- `roleName`
- `description`
- `permissions`

## AI Assistant Layer

### `AgentConfig`

Defines:

- bot identity
- backend endpoint
- greeting text
- quick actions
- fallback responses

### `AgentChatController`

Controls:

- message history
- open / close state
- backend health
- greeting handling
- off-topic filtering

### `AgentChatWidget`

Floating security assistant widget used by the dashboard UI.
