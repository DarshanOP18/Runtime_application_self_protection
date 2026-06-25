// flutter_examples/rasp_api_service.dart
// ───────────────────────────────────────
// Complete Flutter Dart integration for the RASP Security AI Backend.
//
// Uses Dio for HTTP communication with:
// - Retry logic (3 retries on 5xx errors)
// - Typed response models with fromJson factories
// - Custom exception handling
// - Singleton service pattern
//
// USAGE:
//   final result = await RaspApiService.instance.analyzeThreat(payload);

import 'dart:async';
import 'package:dio/dio.dart';

// ═══════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════

/// Base URL for the RASP backend — update this for your deployment.
const String _kBaseUrl = 'http://YOUR_SERVER_IP:8000/api/v1';

// ═══════════════════════════════════════════════════════════════════════
// Exception
// ═══════════════════════════════════════════════════════════════════════

/// Custom exception for RASP API errors.
class RaspApiException implements Exception {
  /// Human-readable error description.
  final String message;

  /// HTTP status code (null for network errors).
  final int? statusCode;

  /// Raw response body, if available.
  final dynamic responseData;

  const RaspApiException({
    required this.message,
    this.statusCode,
    this.responseData,
  });

  @override
  String toString() => 'RaspApiException($statusCode): $message';
}

// ═══════════════════════════════════════════════════════════════════════
// Request / Response Models
// ═══════════════════════════════════════════════════════════════════════

/// Threat payload sent to POST /security/analyze.
class ThreatPayload {
  final String deviceId;
  final int? userId;
  final bool rootDetected;
  final bool fridaDetected;
  final bool debuggerDetected;
  final bool emulatorDetected;
  final bool tamperDetected;
  final bool vpnDetected;
  final bool proxyDetected;
  final bool overlayDetected;
  final bool accessibilityAbuse;
  final bool hookDetected;
  final bool locationSpoof;
  final bool timeSpoof;
  final bool malwareDetected;
  final bool screenshotDetected;
  final String? deviceModel;
  final String? osVersion;
  final String? appVersion;

  const ThreatPayload({
    required this.deviceId,
    this.userId,
    this.rootDetected = false,
    this.fridaDetected = false,
    this.debuggerDetected = false,
    this.emulatorDetected = false,
    this.tamperDetected = false,
    this.vpnDetected = false,
    this.proxyDetected = false,
    this.overlayDetected = false,
    this.accessibilityAbuse = false,
    this.hookDetected = false,
    this.locationSpoof = false,
    this.timeSpoof = false,
    this.malwareDetected = false,
    this.screenshotDetected = false,
    this.deviceModel,
    this.osVersion,
    this.appVersion,
  });

  /// Convert to JSON map for the API request body.
  Map<String, dynamic> toJson() => {
        'device_id': deviceId,
        if (userId != null) 'user_id': userId,
        'root_detected': rootDetected,
        'frida_detected': fridaDetected,
        'debugger_detected': debuggerDetected,
        'emulator_detected': emulatorDetected,
        'tamper_detected': tamperDetected,
        'vpn_detected': vpnDetected,
        'proxy_detected': proxyDetected,
        'overlay_detected': overlayDetected,
        'accessibility_abuse': accessibilityAbuse,
        'hook_detected': hookDetected,
        'location_spoof': locationSpoof,
        'time_spoof': timeSpoof,
        'malware_detected': malwareDetected,
        'screenshot_detected': screenshotDetected,
        if (deviceModel != null) 'device_model': deviceModel,
        if (osVersion != null) 'os_version': osVersion,
        if (appVersion != null) 'app_version': appVersion,
      };
}

/// Parsed response from POST /security/analyze.
class ThreatAnalysisResult {
  final String requestId;
  final String deviceId;
  final String risk;
  final int score;
  final Map<String, dynamic> scoreBreakdown;
  final List<String> activeThreats;
  final String title;
  final String summary;
  final String explanation;
  final String technicalDetail;
  final List<String> recommendation;
  final List<Map<String, dynamic>> remediationSteps;
  final int threatId;
  final String analyzedAt;

  const ThreatAnalysisResult({
    required this.requestId,
    required this.deviceId,
    required this.risk,
    required this.score,
    required this.scoreBreakdown,
    required this.activeThreats,
    required this.title,
    required this.summary,
    required this.explanation,
    required this.technicalDetail,
    required this.recommendation,
    required this.remediationSteps,
    required this.threatId,
    required this.analyzedAt,
  });

  /// Create from JSON response body.
  factory ThreatAnalysisResult.fromJson(Map<String, dynamic> json) {
    return ThreatAnalysisResult(
      requestId: json['request_id'] as String,
      deviceId: json['device_id'] as String,
      risk: json['risk'] as String,
      score: json['score'] as int,
      scoreBreakdown: Map<String, dynamic>.from(json['score_breakdown'] as Map),
      activeThreats: List<String>.from(json['active_threats'] as List),
      title: json['title'] as String,
      summary: json['summary'] as String,
      explanation: json['explanation'] as String,
      technicalDetail: json['technical_detail'] as String,
      recommendation: List<String>.from(json['recommendation'] as List),
      remediationSteps: List<Map<String, dynamic>>.from(
        (json['remediation_steps'] as List).map((e) => Map<String, dynamic>.from(e as Map)),
      ),
      threatId: json['threat_id'] as int,
      analyzedAt: json['analyzed_at'] as String,
    );
  }

  /// Whether the device is in a critical state.
  bool get isCritical => risk == 'CRITICAL';

  /// Whether any threats were detected.
  bool get hasThreats => activeThreats.isNotEmpty;
}

/// Parsed response from POST /security/chat.
class ChatResult {
  final String sessionId;
  final int messageId;
  final String response;
  final List<String> suggestedQuestions;
  final String respondedAt;

  const ChatResult({
    required this.sessionId,
    required this.messageId,
    required this.response,
    required this.suggestedQuestions,
    required this.respondedAt,
  });

  /// Create from JSON response body.
  factory ChatResult.fromJson(Map<String, dynamic> json) {
    return ChatResult(
      sessionId: json['session_id'] as String,
      messageId: json['message_id'] as int,
      response: json['response'] as String,
      suggestedQuestions: List<String>.from(json['suggested_questions'] as List),
      respondedAt: json['responded_at'] as String,
    );
  }
}

/// Parsed response from GET /security/history/{device_id}.
class ThreatHistory {
  final String deviceId;
  final int totalEvents;
  final List<Map<String, dynamic>> events;
  final String riskTrend;
  final String? mostCommonThreat;

  const ThreatHistory({
    required this.deviceId,
    required this.totalEvents,
    required this.events,
    required this.riskTrend,
    this.mostCommonThreat,
  });

  /// Create from JSON response body.
  factory ThreatHistory.fromJson(Map<String, dynamic> json) {
    return ThreatHistory(
      deviceId: json['device_id'] as String,
      totalEvents: json['total_events'] as int,
      events: List<Map<String, dynamic>>.from(
        (json['events'] as List).map((e) => Map<String, dynamic>.from(e as Map)),
      ),
      riskTrend: json['risk_trend'] as String,
      mostCommonThreat: json['most_common_threat'] as String?,
    );
  }
}

/// Dio interceptor that retries requests on 5xx server errors.
class _RetryInterceptor extends Interceptor {
  final Dio dio;
  final int maxRetries;

  _RetryInterceptor({required this.dio, this.maxRetries = 3});

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    final statusCode = err.response?.statusCode ?? 0;
    if (statusCode >= 500 && statusCode < 600) {
      final extra = err.requestOptions.extra;
      final retryCount = (extra['retryCount'] as int?) ?? 0;

      if (retryCount < maxRetries) {
        err.requestOptions.extra['retryCount'] = retryCount + 1;
        await Future.delayed(Duration(seconds: retryCount + 1));

        try {
          final response = await dio.fetch(err.requestOptions);
          handler.resolve(response);
          return;
        } catch (e) {
          // Fall through to default error handling
        }
      }
    }
    handler.next(err);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// RASP API Service (Singleton)
// ═══════════════════════════════════════════════════════════════════════

/// Main service class for interacting with the RASP Security AI Backend.
///
/// Usage:
/// ```dart
/// final service = RaspApiService.instance;
/// final result = await service.analyzeThreat(payload);
/// ```
class RaspApiService {
  // ── Singleton ──────────────────────────────────────────────────────
  static final RaspApiService _instance = RaspApiService._internal();

  /// Global singleton instance.
  static RaspApiService get instance => _instance;

  late final Dio _dio;

  RaspApiService._internal() {
    _dio = Dio(BaseOptions(
      baseUrl: _kBaseUrl,
      connectTimeout: const Duration(seconds: 15),
      receiveTimeout: const Duration(seconds: 120),
      headers: {'Content-Type': 'application/json'},
    ));

    _dio.interceptors.add(_RetryInterceptor(dio: _dio));
  }

  // ── Method 1: Analyse Threat ───────────────────────────────────────

  /// Send a threat payload for analysis.
  ///
  /// Returns a [ThreatAnalysisResult] with risk score, AI explanation,
  /// and remediation steps.
  ///
  /// Throws [RaspApiException] on API errors.
  Future<ThreatAnalysisResult> analyzeThreat(ThreatPayload payload) async {
    try {
      final response = await _dio.post(
        '/security/analyze',
        data: payload.toJson(),
      );
      return ThreatAnalysisResult.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      throw _handleError(e);
    }
  }

  // ── Method 2: Send Chat Message ────────────────────────────────────

  /// Send a security question to the AI chat assistant.
  ///
  /// Returns a [ChatResult] with the AI response and suggested
  /// follow-up questions.
  ///
  /// Throws [RaspApiException] on API errors.
  Future<ChatResult> sendChatMessage(
    String message,
    String sessionId, {
    String? deviceId,
    int? userId,
  }) async {
    try {
      final response = await _dio.post(
        '/security/chat',
        data: {
          'message': message,
          'session_id': sessionId,
          if (deviceId != null) 'device_id': deviceId,
          if (userId != null) 'user_id': userId,
        },
      );
      return ChatResult.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      throw _handleError(e);
    }
  }

  // ── Method 3: Get Threat History ───────────────────────────────────

  /// Fetch threat history for a specific device.
  ///
  /// Returns a [ThreatHistory] with paginated events and risk trend.
  ///
  /// Throws [RaspApiException] on API errors.
  Future<ThreatHistory> getThreatHistory(
    String deviceId, {
    int limit = 20,
    int offset = 0,
  }) async {
    try {
      final response = await _dio.get(
        '/security/history/$deviceId',
        queryParameters: {'limit': limit, 'offset': offset},
      );
      return ThreatHistory.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      throw _handleError(e);
    }
  }

  // ── Method 4: Health Check ─────────────────────────────────────────

  /// Check whether the RASP backend is healthy.
  ///
  /// Returns `true` if the server reports a healthy or degraded status.
  Future<bool> checkHealth() async {
    try {
      final response = await _dio.get('/security/health');
      final status = (response.data as Map<String, dynamic>)['status'];
      return status == 'healthy' || status == 'degraded';
    } catch (_) {
      return false;
    }
  }

  // ── Error Handler ──────────────────────────────────────────────────

  RaspApiException _handleError(DioException error) {
    if (error.response != null) {
      final data = error.response!.data;
      final detail = data is Map ? data['detail'] ?? 'Unknown error' : 'Unknown error';
      return RaspApiException(
        message: detail.toString(),
        statusCode: error.response!.statusCode,
        responseData: data,
      );
    }
    return RaspApiException(
      message: error.message ?? 'Network error — could not reach the server.',
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Example Flutter Widget Usage
// ═══════════════════════════════════════════════════════════════════════

/*
import 'package:flutter/material.dart';

class SecurityDashboard extends StatefulWidget {
  const SecurityDashboard({super.key});

  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard> {
  ThreatAnalysisResult? _lastResult;
  bool _isLoading = false;
  String? _error;

  Future<void> _runSecurityScan() async {
    setState(() { _isLoading = true; _error = null; });

    try {
      final payload = ThreatPayload(
        deviceId: 'my-device-id-123',
        rootDetected: true,
        fridaDetected: false,
        deviceModel: 'Pixel 7',
        osVersion: 'Android 14',
        appVersion: '1.0.0',
      );

      final result = await RaspApiService.instance.analyzeThreat(payload);
      setState(() { _lastResult = result; });
    } on RaspApiException catch (e) {
      setState(() { _error = e.message; });
    } finally {
      setState(() { _isLoading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('RASP Security')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ElevatedButton(
              onPressed: _isLoading ? null : _runSecurityScan,
              child: _isLoading
                  ? const CircularProgressIndicator()
                  : const Text('Run Security Scan'),
            ),
            const SizedBox(height: 16),
            if (_error != null)
              Text('Error: $_error', style: const TextStyle(color: Colors.red)),
            if (_lastResult != null) ...[
              Text('Risk: ${_lastResult!.risk}',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: _lastResult!.isCritical ? Colors.red : Colors.green,
                  )),
              Text('Score: ${_lastResult!.score}'),
              Text('Title: ${_lastResult!.title}'),
              const SizedBox(height: 8),
              Text(_lastResult!.explanation),
              const SizedBox(height: 8),
              const Text('Recommendations:', style: TextStyle(fontWeight: FontWeight.bold)),
              ...(_lastResult!.recommendation.map((r) => Text('• $r'))),
            ],
          ],
        ),
      ),
    );
  }
}
*/
