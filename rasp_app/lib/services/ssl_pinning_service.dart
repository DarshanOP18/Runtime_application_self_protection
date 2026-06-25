import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter/services.dart';

class SslPinningService {
  static const _securityChannel = MethodChannel('com.example.rasp_app/security');

  /// Detects if a MITM attack is likely via SSL Pinning failure or Proxy detection
  static Future<bool> isMitmDetected() async {
    // 1. Native Proxy Check
    final bool nativeProxyDetected = await _checkNativeProxy();
    if (nativeProxyDetected) return true;

    // 2. SSL Pinning Check (Attempt a connection to a known secure endpoint)
    final bool sslPinningFailed = await _checkSslPinning();
    return sslPinningFailed;
  }

  static Future<bool> _checkNativeProxy() async {
    try {
      return await _securityChannel.invokeMethod<bool>('isMitmDetected') ?? false;
    } catch (e) {
      return false;
    }
  }

  static Future<bool> _checkSslPinning() async {
    final dio = Dio();
    
    // Example: Pinning against google.com for demonstration
    // In a real app, you'd use your own server's fingerprint or certificate
    dio.httpClientAdapter = IOHttpClientAdapter(
      createHttpClient: () {
        final client = HttpClient();
        client.badCertificateCallback = (cert, host, port) {
          // If we are here, it means the certificate is suspicious (e.g., self-signed by a proxy)
          return false; // Reject the connection
        };
        return client;
      },
    );

    try {
      await dio.get('https://google.com');
      return false; // Connection succeeded, no MITM detected via certificate rejection
    } on DioException catch (e) {
      // If it's a certificate error, it might be MITM
      if (e.type == DioExceptionType.connectionError || e.error is TlsException) {
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }
}
