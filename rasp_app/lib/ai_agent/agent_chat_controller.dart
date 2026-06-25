import 'dart:async';

import 'package:flutter/foundation.dart';

import 'agent_api_service.dart';
import 'agent_chat_model.dart';
import 'agent_config.dart';

class AgentChatController extends ChangeNotifier {
  final List<ChatMessage> messages = [];
  bool isOpen = false;
  bool isBotTyping = false;
  bool isBackendOnline = false;
  String sessionId = '';
  String deviceId = '';
  int _greetingIndex = 0;
  Timer? _greetingTimer;
  bool _welcomeShown = false;
  String? _lastNotice;
  String? _lastFailedMessage;
  bool _isInitialized = false;

  String? get lastNotice => _lastNotice;
  String? get lastFailedMessage => _lastFailedMessage;

  void initialize(String deviceId) {
    this.deviceId = deviceId.trim().isEmpty
        ? 'guest_device'
        : deviceId.trim();
    sessionId = this.deviceId == 'guest_device'
        ? 'flutter_session_${DateTime.now().millisecondsSinceEpoch}'
        : 'flutter_session_${this.deviceId}';

    if (!_isInitialized) {
      _isInitialized = true;
      unawaited(checkBackendHealth());
      startGreetingCycle();
      notifyListeners();
    }
  }

  void toggleChat() {
    if (isOpen) {
      closeChat();
    } else {
      openChat();
    }
  }

  void openChat() {
    if (isOpen) return;
    isOpen = true;
    stopGreetingCycle();
    _addWelcomeMessage();
    notifyListeners();
  }

  void closeChat() {
    if (!isOpen) return;
    isOpen = false;
    startGreetingCycle();
    notifyListeners();
  }

  Future<void> sendMessage(String text) async {
    final trimmed = text.trim();
    if (trimmed.isEmpty || isBotTyping) {
      return;
    }

    final prepared = _sanitizeMessage(trimmed);
    if (prepared == null) {
      return;
    }

    final userMessage = ChatMessage.fromUser(prepared);
    messages.add(userMessage);
    _lastFailedMessage = null;
    notifyListeners();

    if (_isGreeting(prepared)) {
      messages.add(
        ChatMessage.fromBot(
          'Hello! I\'m RASP Shield AI, your security assistant. I\'m here to help you understand security threats and how to protect your device. What would you like to know?',
          suggestions: const [
            'What threats are detected?',
            'Explain root detection',
            'What is Frida?',
          ],
        ),
      );
      notifyListeners();
      return;
    }

    if (_isOffTopic(prepared)) {
      messages.add(ChatMessage.fromBot(AgentConfig.scopeRefusalMessage));
      notifyListeners();
      return;
    }

    isBotTyping = true;
    messages.add(ChatMessage.typing());
    notifyListeners();

    final response = await AgentApiService.instance.sendMessage(
      message: prepared,
      sessionId: sessionId,
      deviceId: deviceId,
    );

    _removeTypingIndicator();
    isBotTyping = false;

    if (response.isError) {
      final errorText = response.errorMessage ?? AgentConfig.offlineMessage;
      _lastFailedMessage = prepared;
      messages.add(ChatMessage.error(errorText));
    } else {
      messages.add(
        ChatMessage.fromBot(
          response.response,
          suggestions: response.suggestedQuestions,
        ),
      );
    }

    notifyListeners();
  }

  Future<void> sendQuickAction(String action) async {
    await sendMessage(action);
  }

  void startGreetingCycle() {
    _greetingTimer?.cancel();
    if (AgentConfig.greetingMessages.isEmpty) {
      return;
    }

    _greetingTimer = Timer.periodic(const Duration(seconds: 4), (timer) {
      if (isOpen) return;
      _greetingIndex = (_greetingIndex + 1) % AgentConfig.greetingMessages.length;
      notifyListeners();
    });
  }

  void stopGreetingCycle() {
    _greetingTimer?.cancel();
    _greetingTimer = null;
  }

  String get currentGreeting {
    if (AgentConfig.greetingMessages.isEmpty) {
      return '';
    }
    final index = _greetingIndex % AgentConfig.greetingMessages.length;
    return AgentConfig.greetingMessages[index];
  }

  Future<void> checkBackendHealth() async {
    final healthy = await AgentApiService.instance.checkHealth();
    if (isBackendOnline != healthy) {
      isBackendOnline = healthy;
      notifyListeners();
    } else {
      isBackendOnline = healthy;
    }
  }

  void _addWelcomeMessage() {
    if (_welcomeShown) {
      return;
    }

    _welcomeShown = true;
    if (!isBackendOnline) {
      messages.add(ChatMessage.error(AgentConfig.offlineMessage));
      return;
    }

    messages.add(
      ChatMessage.greeting(
        'Hello! I\'m RASP Shield AI, your security assistant. I can explain detected threats, tell you what they mean, and help you fix them.',
      ),
    );
  }

  void clearChat() {
    messages.clear();
    _welcomeShown = false;
    _lastFailedMessage = null;
    notifyListeners();
  }

  void clearNotice() {
    _lastNotice = null;
  }

  String? _sanitizeMessage(String text) {
    if (text.length <= 1000) {
      return text;
    }

    _lastNotice = 'Message truncated to 1000 characters';
    return text.substring(0, 1000);
  }

  bool _isGreeting(String message) {
    final normalized = message.toLowerCase().trim();
    const greetings = <String>[
      'hi',
      'hello',
      'hey',
      'good morning',
      'good evening',
      'good afternoon',
      'good night',
      'howdy',
      'hii',
      'helo',
    ];
    return greetings.contains(normalized);
  }

  bool _isOffTopic(String message) {
    final normalized = message.toLowerCase().trim();
    if (normalized.length <= 10) {
      return false;
    }

    const securityKeywords = <String>[
      'rasp',
      'root',
      'frida',
      'vpn',
      'threat',
      'security',
      'emulator',
      'tamper',
      'hook',
      'detect',
      'safe',
      'risk',
      'block',
      'warning',
      'protection',
      'attack',
      'malware',
      'overlay',
      'accessibility',
      'proxy',
      'debug',
      'jailbreak',
      'ssl',
      'mitm',
      'certificate',
      'device',
      'dangerous',
      'fix',
      'help',
      'what',
      'why',
      'how',
      'explain',
      'is',
    ];

    return !securityKeywords.any((keyword) => normalized.contains(keyword));
  }

  void _removeTypingIndicator() {
    messages.removeWhere((message) => message.isTypingIndicator);
  }

  @override
  void dispose() {
    _greetingTimer?.cancel();
    super.dispose();
  }
}
