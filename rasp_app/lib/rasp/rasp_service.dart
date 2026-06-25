import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:safe_device/safe_device.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'rasp_check_model.dart';
import 'screenshot_restriction.dart';
import '../services/ssl_pinning_service.dart';
import '../services/device_fingerprint_service.dart';
import '../services/threat_reporter_service.dart';
import '../services/geo_filter_service.dart';

class RaspService {
  static const _securityChannel = MethodChannel(
    'com.example.rasp_app/security',
  );

  static DateTime? _lastOnlineTime;

  /// Run all security checks
  static Future<RaspCheckResult> runChecks() async {
    // 1. Original/Native checks
    final isRooted = await _checkRooted();
    final isEmulator = await _checkEmulator();
    final isDebugging = _checkDebugging();
    final isTampered = await _checkAppTampered();
    final screenshotBlockingEnabled =
        await ScreenshotRestriction.enableScreenshotRestriction();

    // 2. Enhanced Native checks
    final isFridaDetected = await _checkFrida();
    final isVpnActive = await _checkVpn();
    final isOverlayDetected = await _checkOverlayAttack();
    final isAccessibilityAbused = await _checkAccessibilityAbuse();
    final isRepackaged = await _checkSignature();

    // 3. Category 1: Advanced checks
    final isCloneDetected = await _checkClone();
    final isDeviceBindingFailed = await _checkDeviceBinding();
    final isOfflineExceeded = await _checkOfflineCompliance();
    final isHighRiskIp = await GeoFilterService.isHighRiskIp();

    // 4. Service-based checks
    final isMitmDetected = await SslPinningService.isMitmDetected();
    final fingerprintResult = await DeviceFingerprintService.checkDeviceRisk();

    // Setup screenshot detection listener for iOS
    ScreenshotRestriction.setupScreenshotDetectionListener();

    final result = RaspCheckResult(
      isRooted: isRooted,
      isEmulator: isEmulator,
      isDebugging: isDebugging,
      isTampered: isTampered,
      isBlockingEnforced: kReleaseMode,
      screenshotBlockingEnabled: screenshotBlockingEnabled,
      isFridaDetected: isFridaDetected,
      isVpnActive: isVpnActive,
      isMitmDetected: isMitmDetected,
      isRepackaged: isRepackaged,
      hasReverseEngineeringTools: await _checkReverseEngineeringTools(),
      isOverlayDetected: isOverlayDetected,
      isAccessibilityAbused: isAccessibilityAbused,
      isDeviceRisk: fingerprintResult.isRisk,
      deviceRiskReason: fingerprintResult.reason,
      // Category 1 results
      isCloneDetected: isCloneDetected,
      isDeviceBindingFailed: isDeviceBindingFailed,
      isHighRiskIp: isHighRiskIp,
      isOfflineExceeded: isOfflineExceeded,
      useDeceptiveResponse: _shouldEnableDeception(isFridaDetected || isRooted),
    );

    // 5. Report threats if any detected
    if (result.isThreatDetected) {
      ThreatReporterService.reportThreat(result.threatSummary);
    }

    return result;
  }

  /// CHECK: App Cloning / Dual Open Detection
  static Future<bool> _checkClone() async {
    if (!_isAndroid) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('isCloneDetected') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Device Binding (Hardware-backed Keystore)
  static Future<bool> _checkDeviceBinding() async {
    if (!_isAndroid) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('verifyDeviceBinding') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Offline Compliance (Max 30 mins offline)
  static Future<bool> _checkOfflineCompliance() async {
    final connectivityResults = await Connectivity().checkConnectivity();
    final bool isOnline = connectivityResults.isNotEmpty &&
        !connectivityResults.contains(ConnectivityResult.none);

    if (isOnline) {
      _lastOnlineTime = DateTime.now();
      return false;
    }

    if (_lastOnlineTime == null) {
      _lastOnlineTime = DateTime.now(); // Assume online at start
      return false;
    }

    final offlineDuration = DateTime.now().difference(_lastOnlineTime!);
    return offlineDuration.inMinutes > 30;
  }

  /// LOGIC: Decide if we should show a fake screen instead of blocking
  static bool _shouldEnableDeception(bool criticalThreat) {
    // In a real app, this might be toggled via Remote Config
    // For demo: if Frida or Root is found, we can optionally deceive
    return criticalThreat; 
  }

  /// Check if device is rooted (Android) or jailbroken (iOS)
  static Future<bool> _checkRooted() async {
    if (!_supportsSafeDeviceChecks) return false;
    try {
      return await SafeDevice.isJailBroken;
    } catch (e) {
      return false;
    }
  }

  /// Check if running on emulator/simulator
  static Future<bool> _checkEmulator() async {
    if (!_supportsSafeDeviceChecks) return false;
    try {
      return await SafeDevice.isRealDevice == false;
    } catch (e) {
      return false;
    }
  }

  /// Check if debugger is attached
  static bool _checkDebugging() {
    return kDebugMode;
  }

  /// CHECK: App Tampering (Enhanced Integrity)
  static Future<bool> _checkAppTampered() async {
    if (!_isAndroid) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('isAppTampered') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Frida Framework Detection
  static Future<bool> _checkFrida() async {
    if (!_supportsSafeDeviceChecks) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('detectFrida') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: VPN Detection
  static Future<bool> _checkVpn() async {
    if (!_supportsSafeDeviceChecks) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('isVpnActive') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Signature Check (Repackaging)
  static Future<bool> _checkSignature() async {
    if (!_isAndroid) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('verifySignature') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Overlay Attack Detection
  static Future<bool> _checkOverlayAttack() async {
    if (!_isAndroid) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('isOverlayAttackDetected') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Accessibility Abuse Detection
  static Future<bool> _checkAccessibilityAbuse() async {
    if (!_isAndroid) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('isAccessibilityAbused') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// CHECK: Reverse Engineering Tools Detection
  static Future<bool> _checkReverseEngineeringTools() async {
    if (!_supportsSafeDeviceChecks) return false;
    try {
      return await _securityChannel.invokeMethod<bool>('checkReverseEngineeringTools') ?? false;
    } catch (e) {
      return false;
    }
  }

  static bool get _supportsSafeDeviceChecks =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  static bool get _isAndroid =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;
}
