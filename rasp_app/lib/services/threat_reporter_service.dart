import 'package:flutter/foundation.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'dart:io';

class ThreatReporterService {
  /// Silently sends threat data to Firestore
  static Future<void> reportThreat(String threatSummary) async {
    try {
      final firebaseReady = await _ensureFirebaseReady();
      if (!firebaseReady) {
        return;
      }

      final deviceInfo = DeviceInfoPlugin();
      String deviceId = 'unknown';
      if (Platform.isAndroid) {
        final androidInfo = await deviceInfo.androidInfo;
        deviceId = androidInfo.id;
      } else if (Platform.isIOS) {
        final iosInfo = await deviceInfo.iosInfo;
        deviceId = iosInfo.identifierForVendor ?? 'unknown';
      }

      final packageInfo = await PackageInfo.fromPlatform();

      final data = {
        "deviceId": deviceId,
        "threatType": threatSummary,
        "timestamp": DateTime.now().toIso8601String(),
        "appVersion": packageInfo.version,
        "platform": Platform.isAndroid ? "android" : "ios"
      };

      // Firestore is best-effort telemetry. Fail closed by doing nothing.
      try {
        await FirebaseFirestore.instance.collection('rasp_threats').add(data);
      } catch (e) {
        debugPrint('Threat report failed (Firebase): $e');
      }
    } catch (e) {
      debugPrint('Threat report failed: $e');
    }
  }

  static Future<bool> _ensureFirebaseReady() async {
    try {
      if (Firebase.apps.isNotEmpty) {
        return true;
      }
      await Firebase.initializeApp();
      return Firebase.apps.isNotEmpty;
    } catch (_) {
      return false;
    }
  }
}
