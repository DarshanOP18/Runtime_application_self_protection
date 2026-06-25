import Flutter
import UIKit
import NetworkExtension

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  private var screenshotMethodChannel: FlutterMethodChannel?
  private var securityChannel: FlutterMethodChannel?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    let controller = window?.rootViewController as! FlutterViewController

    screenshotMethodChannel = FlutterMethodChannel(
      name: "com.example.rasp_app/screenshot",
      binaryMessenger: controller.binaryMessenger
    )

    screenshotMethodChannel?.setMethodCallHandler { [weak self] (call: FlutterMethodCall, result: @escaping FlutterResult) in
      switch call.method {
      case "enableScreenshotRestriction":
        self?.enableScreenshotDetection()
        result(true)
      case "disableScreenshotRestriction":
        self?.disableScreenshotDetection()
        result(false)
      case "isScreenshotBlockingActive":
        result(true)
      default:
        result(FlutterMethodNotImplemented)
      }
    }

    // Security channel (ALIGNED WITH ANDROID)
    securityChannel = FlutterMethodChannel(
      name: "com.example.rasp_app/security",
      binaryMessenger: controller.binaryMessenger
    )

    securityChannel?.setMethodCallHandler { [weak self] (call: FlutterMethodCall, result: @escaping FlutterResult) in
      switch call.method {
      case "isVpnActive":
        result(self?.isVpnActive() ?? false)
      case "isMitmDetected":
        result(self?.isMitmDetected() ?? false)
      case "checkReverseEngineeringTools":
        result(self?.hasReverseEngineeringTools() ?? false)
      case "detectFrida":
        result(self?.isFridaDetected() ?? false)
      case "getDeviceFingerprint":
        result(self?.getDeviceFingerprint() ?? "{}")
      case "applyBackgroundBlur":
        self?.applyBackgroundBlur()
        result(true)
      case "removeBackgroundBlur":
        self?.removeBackgroundBlur()
        result(true)
      case "isAppTampered":
        result(false) // Placeholder
      case "verifySignature":
        result(false) // Placeholder
      default:
        result(FlutterMethodNotImplemented)
      }
    }

    // Start listening for screenshots
    self.enableScreenshotDetection()

    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
  }

  // MARK: - Background Blur (Privacy Shield)

  private var blurView: UIVisualEffectView?

  private func applyBackgroundBlur() {
    if blurView == nil {
      let blurEffect = UIBlurEffect(style: .dark)
      blurView = UIVisualEffectView(effect: blurEffect)
      blurView?.frame = window?.bounds ?? UIScreen.main.bounds
    }
    window?.addSubview(blurView!)
  }

  private func removeBackgroundBlur() {
    blurView?.removeFromSuperview()
  }

  // MARK: - Screenshot Detection

  private func enableScreenshotDetection() {
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(screenshotTaken),
      name: UIApplication.userDidTakeScreenshotNotification,
      object: nil
    )
  }

  private func disableScreenshotDetection() {
    NotificationCenter.default.removeObserver(
      self,
      name: UIApplication.userDidTakeScreenshotNotification,
      object: nil
    )
  }

  @objc func screenshotTaken() {
    // Notify Dart layer that a screenshot was taken
    screenshotMethodChannel?.invokeMethod("onScreenshotDetected", arguments: nil)

    // Show alert to user
    if let window = UIApplication.shared.windows.first,
       let rootViewController = window.rootViewController {
      let alert = UIAlertController(
        title: "Screenshot Blocked",
        message: "Screenshots are not allowed in this application for security reasons.",
        preferredStyle: .alert
      )
      alert.addAction(UIAlertAction(title: "OK", style: .default))
      rootViewController.present(alert, animated: true)
    }
  }

  // MARK: - Enhanced Security Checks (NEW)

  private func isVpnActive() -> Bool {
    // Check for active VPN on iOS
    guard let settings = CFNetworkCopySystemProxySettings() else { return false }
    let proxies = settings.takeRetainedValue() as NSDictionary

    // Check for VPN proxy settings
    if let httpProxy = proxies["HTTPProxy"] as? String,
       !httpProxy.isEmpty {
      return true
    }

    if let httpsProxy = proxies["HTTPSProxy"] as? String,
       !httpsProxy.isEmpty {
      return true
    }

    return false
  }

  private func hasReverseEngineeringTools() -> Bool {
    // Check for common jailbreak and RE tools on iOS
    let jailbreakPaths = [
      "/Applications/Cydia.app",
      "/Applications/FakeCarrier.app",
      "/Applications/Icy.app",
      "/Applications/SBSettings.app",
      "/Applications/WinterBoard.app",
      "/bin/bash",
      "/private/var/stash",
      "/private/var/mobile/Library/SBSettings",
      "/usr/bin/sshd",
      "/usr/sbin/sshd",
      "/private/etc/ssh/sshd_config",
    ]

    return jailbreakPaths.contains { path in
      FileManager.default.fileExists(atPath: path)
    }
  }

  private func isFridaDetected() -> Bool {
    // Check for Frida-related artifacts on iOS
    let fridaPaths = [
      "/usr/lib/libfrida.dylib",
      "/usr/local/lib/libfrida.dylib",
    ]

    return fridaPaths.contains { path in
      FileManager.default.fileExists(atPath: path)
    }
  }

  private func isMitmDetected() -> Bool {
    // Simple proxy check for iOS
    guard let settings = CFNetworkCopySystemProxySettings() else { return false }
    let proxies = settings.takeRetainedValue() as NSDictionary

    if let httpProxy = proxies["HTTPProxy"] as? String, !httpProxy.isEmpty {
      return true
    }
    if let httpsProxy = proxies["HTTPSProxy"] as? String, !httpsProxy.isEmpty {
      return true
    }
    return false
  }

  private func getDeviceFingerprint() -> String {
    let device = UIDevice.current
    var fingerprint: [String: Any] = [:]

    fingerprint["model"] = device.model
    fingerprint["name"] = device.name
    fingerprint["systemName"] = device.systemName
    fingerprint["systemVersion"] = device.systemVersion
    fingerprint["identifierForVendor"] = device.identifierForVendor?.uuidString ?? "unknown"

    // Check if passcode is enabled (best effort)
    // On iOS, we can check if data protection is available
    let fileManager = FileManager.default
    if let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first {
      do {
        let attributes = try fileManager.attributesOfItem(atPath: documentsDirectory.path)
        if let protectionKey = attributes[.protectionKey] as? FileProtectionType {
          fingerprint["screenLockEnabled"] = (protectionKey != .none)
        } else {
          fingerprint["screenLockEnabled"] = false
        }
      } catch {
        fingerprint["screenLockEnabled"] = false
      }
    }

    // Convert to JSON string
    if let jsonData = try? JSONSerialization.data(withJSONObject: fingerprint, options: []),
       let jsonString = String(data: jsonData, encoding: .utf8) {
      return jsonString
    }

    return "{}"
  }
}

