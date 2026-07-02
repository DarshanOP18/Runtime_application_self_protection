import '../services/backend_config.dart';

class AgentConfig {
  // Backend connection
  static const String baseUrl = BackendConfig.securityApiBaseUrl;

  // Bot personality
  static const String botName = 'RASP Shield AI';
  static const String botTagline = 'Your Security Assistant';
  static const String botAvatar = 'assets/images/bot_icon.webp';

  // Greeting messages - bot cycles through these on dashboard load
  static const List<String> greetingMessages = [
    ' Hey! Need help with your security status?',
    '️ High five! Your RASP Shield is active.',
    '✅ All security checks running. Any questions?',
    ' Monitoring threats in real-time. Ask me anything!',
    ' Security Assistant ready. How can I help?',
  ];

  // Quick action buttons shown before user types
  static const List<String> quickActions = [
    'What threats are detected?',
    'Explain root detection',
    'Is my device safe?',
    'What is Frida?',
    'How to fix VPN warning?',
    'Which threat is most dangerous?',
  ];

  // Offline/error fallback response
  static const String offlineMessage =
      'I am currently offline. Please check that the security backend is running at $baseUrl and try again.';

  // Scope guard - bot refuses off-topic questions
  static const String scopeRefusalMessage =
      'I am specialized only in RASP security features for this app. I can help you understand detected threats, security risks, and how to resolve them. Please ask me a security-related question!';
}
