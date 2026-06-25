import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'dart:io';

class ThreatReporterService {
  /// Silently sends threat data to Firestore
  static Future<void> reportThreat(String threatSummary) async {
    try {
      // Check if Firebase is initialized. 
      // TODO: add google-services.json to enable Firebase properly
      
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

      // Silently attempt to send to Firestore
      // Using a try-catch inside to avoid crashing the app if Firebase is not setup
      try {
        await FirebaseFirestore.instance.collection('rasp_threats').add(data);
      } catch (e) {
        // Firebase probably not initialized or no network
        print('Threat report failed (Firebase): $e');
      }
    } catch (e) {
      print('Threat report failed: $e');
    }
  }
}
