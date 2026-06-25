# Installation Guide

## Prerequisites

- Flutter SDK compatible with the `sdk` constraint in `pubspec.yaml`
- Android Studio / Xcode if you plan to target mobile platforms
- Optional: Firebase project if you want threat reports written to Firestore

## Clone and Install

```bash
git clone https://github.com/DarshanOP18/Runtime-Application-and-Self-Protection---App-SDK.git
cd Runtime-Application-and-Self-Protection---App-SDK
flutter pub get
```

## Platform Setup

### Android

- Ensure your Android signing configuration is ready before release.
- If you use native MethodChannel hooks, keep the Android implementation in sync with `lib/rasp/RaspService`.
- Verify your `minSdkVersion` and Gradle configuration support the dependency set in `pubspec.yaml`.

### iOS

- Run `pod install` from `ios/` when native pods change.
- Make sure screenshot detection and security listeners are wired through the iOS host app if you use them.

### Firebase

If you want threat reporting:

1. Add your Firebase app configuration files.
2. Initialize Firebase before calling `ThreatReporterService.reportThreat`.
3. Confirm Firestore permissions are appropriate for the deployment environment.

## Verify the Build

```bash
flutter analyze
flutter test
flutter build apk --release
```

## Recommended Release Checks

- Verify login and session persistence.
- Verify the RASP dashboard loads after a clean device check.
- Verify threat reporting is disabled or configured correctly in non-production environments.
- Verify the bot opens only when tapped.
