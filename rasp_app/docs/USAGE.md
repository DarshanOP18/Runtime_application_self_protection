# Usage Examples

## 1. Run the RASP checks

```dart
final result = await RaspService.runChecks();

if (result.shouldBlockApp) {
  // Show a blocked or deceptive screen.
}
```

## 2. Read the results

```dart
if (result.isRooted) {
  // Root / jailbreak signal
}

if (result.isFridaDetected) {
  // Frida signal
}

if (result.isMitmDetected) {
  // SSL interception / MITM signal
}
```

## 3. Validate screenshot protection

```dart
final enabled = await ScreenshotRestriction.enableScreenshotRestriction();
```

## 4. React to screenshot events

```dart
ScreenshotRestriction.setScreenshotDetectedCallback(() {
  // Trigger an alert, lock the screen, or log telemetry.
});
```

## 5. Use the RBAC repository

```dart
final userRepo = UserRepository();
final user = await userRepo.loginUser(email, password);
```

## 6. Show the security assistant

```dart
AgentChatWidget(deviceId: 'device-123')
```

## 7. Handle verified users

```dart
final upgraded = await userRepo.verifyAndUpgradeUser(userId);
```

## Notes

- Keep security checks server-aligned when you use this SDK in production.
- Prefer blocking or review flows for high-risk signals.
- Treat AI chat as guidance, not as an enforcement engine.
