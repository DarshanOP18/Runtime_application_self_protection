import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

class GeoFilterService {
  /// Check if the current IP belongs to a high-risk country or a known VPN/Proxy
  static Future<bool> isHighRiskIp() async {
    if (kDebugMode) return false; // Skip in debug

    try {
      final dio = Dio();
      // Using a free IP info API for demonstration
      // In production, use a professional service like ipstack, cloudflare, or maxmind
      final response = await dio.get('https://ipapi.co/json/');
      
      if (response.statusCode == 200) {
        final data = response.data;
        final country = data['country_code'] as String?;
        
        // Example: Block specific high-risk countries
        const blockedCountries = ['KP', 'IR', 'SY'];
        if (blockedCountries.contains(country)) {
          return true;
        }

        // Check for Proxy/VPN indicators (if the API provides them)
        // Some APIs provide 'security' or 'proxy' fields
        final isProxy = data['proxy'] ?? false;
        if (isProxy == true) {
          return true;
        }
      }
      return false;
    } catch (e) {
      // If we can't check, we might want to fail-safe (allow) or fail-closed (block)
      // For this demo, we allow if the check fails due to network
      return false;
    }
  }
}
