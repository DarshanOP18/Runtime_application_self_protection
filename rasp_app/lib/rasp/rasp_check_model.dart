class RaspCheckResult {
  // Original checks (DO NOT MODIFY)
  final bool isRooted;
  final bool isEmulator;
  final bool isDebugging;
  final bool isTampered;
  final bool isBlockingEnforced;
  final bool screenshotBlockingEnabled;

  // New enhanced checks (ADDED LAYERS)
  final bool isFridaDetected;
  final bool isVpnActive;
  final bool isMitmDetected;
  final bool isRepackaged;
  final bool hasReverseEngineeringTools;
  final bool isOverlayDetected;
  final bool isAccessibilityAbused;
  final bool isDeviceRisk;
  final String deviceRiskReason;

  // Category 1: Advanced Features
  final bool isCloneDetected;
  final bool isDeviceBindingFailed;
  final bool isHighRiskIp;
  final bool isOfflineExceeded;
  final bool useDeceptiveResponse;

  const RaspCheckResult({
    required this.isRooted,
    required this.isEmulator,
    required this.isDebugging,
    required this.isTampered,
    required this.isBlockingEnforced,
    this.screenshotBlockingEnabled = false,
    // New parameters
    this.isFridaDetected = false,
    this.isVpnActive = false,
    this.isMitmDetected = false,
    this.isRepackaged = false,
    this.hasReverseEngineeringTools = false,
    this.isOverlayDetected = false,
    this.isAccessibilityAbused = false,
    this.isDeviceRisk = false,
    this.deviceRiskReason = '',
    // Category 1 parameters
    this.isCloneDetected = false,
    this.isDeviceBindingFailed = false,
    this.isHighRiskIp = false,
    this.isOfflineExceeded = false,
    this.useDeceptiveResponse = false,
  });

  bool get isThreatDetected =>
      isRooted ||
      isEmulator ||
      isDebugging ||
      isTampered ||
      isFridaDetected ||
      isVpnActive ||
      isMitmDetected ||
      isRepackaged ||
      hasReverseEngineeringTools ||
      isOverlayDetected ||
      isAccessibilityAbused ||
      isDeviceRisk ||
      isCloneDetected ||
      isDeviceBindingFailed ||
      isHighRiskIp ||
      isOfflineExceeded;

  bool get shouldBlockApp => isBlockingEnforced && isThreatDetected && !useDeceptiveResponse;
  bool get shouldShowDeception => isBlockingEnforced && isThreatDetected && useDeceptiveResponse;

  String get threatSummary {
    final threats = <String>[];
    // Original threats
    if (isRooted) threats.add("Rooted/Jailbroken Device");
    if (isEmulator) threats.add("Emulator Detected");
    if (isDebugging) threats.add("Debug Build");
    if (isTampered) threats.add("App Integrity Compromised");
    // New threats
    if (isFridaDetected) threats.add("Frida Framework Detected");
    if (isVpnActive) threats.add("VPN Connection Active");
    if (isMitmDetected) threats.add("SSL / MITM Attack Detected");
    if (isRepackaged) threats.add("App Signature Invalid / Tampered");
    if (hasReverseEngineeringTools) threats.add("RE Tools Detected");
    if (isOverlayDetected) threats.add("Overlay Attack Detected");
    if (isAccessibilityAbused) threats.add("Accessibility Abuse Detected");
    if (isDeviceRisk) threats.add("Device Risk: $deviceRiskReason");
    // Category 1 threats
    if (isCloneDetected) threats.add("Dual App / Clone Detected");
    if (isDeviceBindingFailed) threats.add("Device Binding Integrity Failed");
    if (isHighRiskIp) threats.add("High Risk IP / Geofence Block");
    if (isOfflineExceeded) threats.add("Offline Compliance Timeout");
    return threats.isEmpty ? "No Threats" : threats.join(", ");
  }
}
