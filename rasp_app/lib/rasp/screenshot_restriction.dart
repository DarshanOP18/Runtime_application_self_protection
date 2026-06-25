import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';

class ScreenshotRestriction {
  static const platform = MethodChannel('com.example.rasp_app/screenshot');
  static bool _listenerSetup = false;

  /// Enable screenshot blocking (Android) and detection (iOS)
  static Future<bool> enableScreenshotRestriction() async {
    try {
      // Setup listener on first enable
      if (!_listenerSetup) {
        setupScreenshotDetectionListener();
      }

      final bool result =
          await platform.invokeMethod<bool>('enableScreenshotRestriction') ??
          false;
      if (kDebugMode) {
        print('Screenshot restriction enabled: $result');
      }
      return result;
    } catch (e) {
      if (kDebugMode) {
        print('Error enabling screenshot restriction: $e');
      }
      return false;
    }
  }

  /// Disable screenshot blocking
  static Future<bool> disableScreenshotRestriction() async {
    try {
      final bool result =
          await platform.invokeMethod<bool>('disableScreenshotRestriction') ??
          false;
      if (kDebugMode) {
        print('Screenshot restriction disabled: $result');
      }
      return result;
    } catch (e) {
      if (kDebugMode) {
        print('Error disabling screenshot restriction: $e');
      }
      return false;
    }
  }

  /// Check if screenshot blocking is currently active
  static Future<bool> isScreenshotBlockingActive() async {
    try {
      final bool result =
          await platform.invokeMethod<bool>('isScreenshotBlockingActive') ??
          false;
      return result;
    } catch (e) {
      if (kDebugMode) {
        print('Error checking screenshot blocking status: $e');
      }
      return false;
    }
  }

  /// Setup listener for screenshot detection (iOS) and blocking notifications
  static void setupScreenshotDetectionListener() {
    if (_listenerSetup) return;

    platform.setMethodCallHandler((MethodCall call) async {
      if (call.method == 'onScreenshotDetected') {
        if (kDebugMode) {
          print('Screenshot detected/blocked on device');
        }
        _onScreenshotDetected();
      }
      return null;
    });

    _listenerSetup = true;
  }

  /// Callback when screenshot is detected
  static Function? _screenshotDetectedCallback;

  static void setScreenshotDetectedCallback(Function callback) {
    _screenshotDetectedCallback = callback;
  }

  static void _onScreenshotDetected() {
    _screenshotDetectedCallback?.call();
  }

  /// Reset listener (for cleanup)
  static void resetListener() {
    _listenerSetup = false;
    _screenshotDetectedCallback = null;
  }
}
