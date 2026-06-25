import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceFingerprintResult {
  final bool isRisk;
  final String reason;
  final List<String> failedChecks;

  DeviceFingerprintResult({
    required this.isRisk,
    required this.reason,
    required this.failedChecks,
  });
}

class DeviceFingerprintService {
  static const _storage = FlutterSecureStorage();
  static const _key = 'device_fingerprint_v2';
  static const _securityChannel = MethodChannel('com.example.rasp_app/security');

  // HOW TO TEST:
  // screenLockEnabled → Go to Settings > Security > Screen Lock > set to None
  // adbEnabled → Go to Settings > Developer Options > turn on USB Debugging
  // selinuxEnforcing → Requires rooted device to disable (rarely possible on non-root)
  // installSource → Install app via "flutter run" (not Play Store) triggers this
  // Hardware change → Use "Device ID Changer" app from Play Store (requires root)

  static Future<DeviceFingerprintResult> checkDeviceRisk() async {
    try {
      final String jsonString = await _securityChannel.invokeMethod('getDeviceFingerprint') ?? '{}';
      final Map<String, dynamic> data = jsonDecode(jsonString);

      List<String> failedChecks = [];

      // 1. Immediate Security Checks
      if (data['screenLockEnabled'] == false) {
        failedChecks.add('Screen Lock Disabled');
      }
      if (data['adbEnabled'] == true) {
        failedChecks.add('ADB Debugging Enabled');
      }
      if (data['selinuxEnforcing'] == false) {
        failedChecks.add('SELinux Permissive');
      }
      
      final String installSource = data['installSource'] ?? 'unknown';
      if (installSource != 'com.android.vending' && installSource != 'amazon.market.appstore') {
        // We allow some common stores, but mark others as risk (like sideloaded via ADB)
        failedChecks.add('Sideloaded (Source: $installSource)');
      }

      // 2. Hardware Baseline Check
      String hardwareId;
      if (data.containsKey('androidId')) {
        // Android-specific baseline
        hardwareId = '${data['androidId']}|${data['model']}|${data['board']}|${data['buildFingerprint']}';
      } else {
        // iOS-specific baseline
        hardwareId = '${data['identifierForVendor']}|${data['model']}|${data['systemName']}|${data['systemVersion']}';
      }
      
      final bytes = utf8.encode(hardwareId);
      final currentHash = sha256.convert(bytes).toString();

      final storedHash = await _storage.read(key: _key);
      if (storedHash == null) {
        await _storage.write(key: _key, value: currentHash);
      } else if (storedHash != currentHash) {
        failedChecks.add('Hardware Identity Changed');
      }

      bool isRisk = failedChecks.isNotEmpty;
      return DeviceFingerprintResult(
        isRisk: isRisk,
        reason: failedChecks.join(', '),
        failedChecks: failedChecks,
      );
    } catch (e) {
      return DeviceFingerprintResult(
        isRisk: false,
        reason: '',
        failedChecks: [],
      );
    }
  }
}
