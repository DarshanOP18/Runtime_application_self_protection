import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'agent_config.dart';

class AgentChatResponse {
  final String response;
  final List<String> suggestedQuestions;
  final bool isError;
  final String? errorMessage;

  const AgentChatResponse({
    required this.response,
    required this.suggestedQuestions,
    required this.isError,
    this.errorMessage,
  });

  factory AgentChatResponse.fromJson(Map<String, dynamic> json) {
    final suggestions = <String>[];
    final rawSuggestions = json['suggested_questions'];
    if (rawSuggestions is List) {
      for (final item in rawSuggestions) {
        if (item != null) {
          suggestions.add(item.toString());
        }
      }
    }

    return AgentChatResponse(
      response: (json['response'] ?? json['message'] ?? '').toString(),
      suggestedQuestions: suggestions,
      isError: false,
    );
  }

  factory AgentChatResponse.error(String message) {
    return AgentChatResponse(
      response: message,
      suggestedQuestions: const [],
      isError: true,
      errorMessage: message,
    );
  }
}

class AgentApiService {
  late final Dio _dio;
  static AgentApiService? _instance;

  static AgentApiService get instance => _instance ??= AgentApiService._();

  AgentApiService._() {
    _dio = Dio(
      BaseOptions(
        baseUrl: AgentConfig.baseUrl,
        connectTimeout: const Duration(seconds: 10),
        receiveTimeout: const Duration(seconds: 30),
        headers: <String, dynamic>{
          'Content-Type': 'application/json',
        },
      ),
    );

    if (kDebugMode) {
      _dio.interceptors.add(
        LogInterceptor(
          requestBody: true,
          responseBody: true,
          error: true,
        ),
      );
    }
  }

  Future<AgentChatResponse> sendMessage({
    required String message,
    required String sessionId,
    required String deviceId,
  }) async {
    final payload = <String, dynamic>{
      'message': message,
      'session_id': sessionId,
      'device_id': deviceId,
    };

    try {
      final response = await _postWithRetry<Map<String, dynamic>>(
        '/security/chat',
        payload,
      );
      final data = response.data;
      if (data is Map<String, dynamic>) {
        return AgentChatResponse.fromJson(data);
      }
      return AgentChatResponse.error('Unexpected response format from AI backend.');
    } on DioException catch (e) {
      return AgentChatResponse.error(_mapDioError(e));
    } catch (e) {
      return AgentChatResponse.error('Unexpected error while contacting the AI backend.');
    }
  }

  Future<bool> checkHealth() async {
    try {
      final response = await _postOrGetWithRetry<Map<String, dynamic>>(
        method: 'GET',
        path: '/security/health',
      );

      final data = response.data;
      if (data is Map<String, dynamic>) {
        return data['status']?.toString().toLowerCase() == 'healthy';
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  Future<Map<String, dynamic>?> analyzeThreats({
    required String deviceId,
    required Map<String, bool> threatFlags,
  }) async {
    final payload = <String, dynamic>{
      'device_id': deviceId,
      ...threatFlags,
    };

    try {
      final response = await _postWithRetry<Map<String, dynamic>>(
        '/security/analyze',
        payload,
      );
      final data = response.data;
      if (data is Map<String, dynamic>) {
        return data;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  Future<Response<T>> _postWithRetry<T>(
    String path,
    Object? data,
  ) async {
    return _requestWithRetry<T>(
      () => _dio.post<T>(path, data: data),
    );
  }

  Future<Response<T>> _postOrGetWithRetry<T>({
    required String method,
    required String path,
    Object? data,
  }) async {
    return _requestWithRetry<T>(
      () async {
        switch (method) {
          case 'GET':
            return _dio.get<T>(path);
          case 'POST':
            return _dio.post<T>(path, data: data);
          default:
            throw UnsupportedError('Unsupported method: $method');
        }
      },
    );
  }

  Future<Response<T>> _requestWithRetry<T>(
    Future<Response<T>> Function() request,
  ) async {
    DioException? lastError;
    for (var attempt = 0; attempt < 3; attempt++) {
      try {
        return await request();
      } on DioException catch (e) {
        lastError = e;
        if (!_isRetriable(e) || attempt == 2) {
          rethrow;
        }
        await Future<void>.delayed(Duration(milliseconds: 250 * (attempt + 1)));
      }
    }
    throw lastError ?? DioException(
      requestOptions: RequestOptions(path: ''),
      error: 'Request failed',
      type: DioExceptionType.unknown,
    );
  }

  bool _isRetriable(DioException error) {
    return error.type == DioExceptionType.connectionError ||
        error.type == DioExceptionType.connectionTimeout ||
        error.type == DioExceptionType.receiveTimeout ||
        error.type == DioExceptionType.sendTimeout;
  }

  String _mapDioError(DioException error) {
    if (error.type == DioExceptionType.connectionTimeout ||
        error.type == DioExceptionType.receiveTimeout ||
        error.type == DioExceptionType.sendTimeout) {
      return 'Request timed out. Please try again.';
    }

    if (error.type == DioExceptionType.connectionError) {
      return AgentConfig.offlineMessage;
    }

    final statusCode = error.response?.statusCode;
    if (statusCode != null) {
      return 'AI backend returned HTTP $statusCode.';
    }

    final responseData = error.response?.data;
    if (responseData is Map<String, dynamic>) {
      final message = responseData['detail']?.toString() ??
          responseData['message']?.toString();
      if (message != null && message.isNotEmpty) {
        return message;
      }
    }

    return 'Unable to reach the AI backend.';
  }
}
