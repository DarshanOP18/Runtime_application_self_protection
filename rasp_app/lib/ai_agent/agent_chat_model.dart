enum MessageSender { user, bot, system }

enum MessageStatus { sending, delivered, error }

class ChatMessage {
  final String id;
  final String text;
  final MessageSender sender;
  final DateTime timestamp;
  final MessageStatus status;
  final List<String> suggestedQuestions;
  final bool isGreeting;
  final bool isTypingIndicator;

  const ChatMessage({
    required this.id,
    required this.text,
    required this.sender,
    required this.timestamp,
    this.status = MessageStatus.delivered,
    this.suggestedQuestions = const [],
    this.isGreeting = false,
    this.isTypingIndicator = false,
  });

  ChatMessage copyWith({MessageStatus? status, String? text}) {
    return ChatMessage(
      id: id,
      text: text ?? this.text,
      sender: sender,
      timestamp: timestamp,
      status: status ?? this.status,
      suggestedQuestions: suggestedQuestions,
      isGreeting: isGreeting,
      isTypingIndicator: isTypingIndicator,
    );
  }

  factory ChatMessage.fromUser(String text) {
    final now = DateTime.now();
    return ChatMessage(
      id: now.millisecondsSinceEpoch.toString(),
      text: text,
      sender: MessageSender.user,
      timestamp: now,
      status: MessageStatus.delivered,
    );
  }

  factory ChatMessage.fromBot(String text, {List<String> suggestions = const []}) {
    final now = DateTime.now();
    return ChatMessage(
      id: now.millisecondsSinceEpoch.toString(),
      text: text,
      sender: MessageSender.bot,
      timestamp: now,
      status: MessageStatus.delivered,
      suggestedQuestions: suggestions,
    );
  }

  factory ChatMessage.typing() {
    final now = DateTime.now();
    return ChatMessage(
      id: now.millisecondsSinceEpoch.toString(),
      text: '...',
      sender: MessageSender.bot,
      timestamp: now,
      status: MessageStatus.sending,
      isTypingIndicator: true,
    );
  }

  factory ChatMessage.error(String reason) {
    final now = DateTime.now();
    return ChatMessage(
      id: now.millisecondsSinceEpoch.toString(),
      text: reason,
      sender: MessageSender.bot,
      timestamp: now,
      status: MessageStatus.error,
    );
  }

  factory ChatMessage.greeting(String text) {
    final now = DateTime.now();
    return ChatMessage(
      id: now.millisecondsSinceEpoch.toString(),
      text: text,
      sender: MessageSender.bot,
      timestamp: now,
      status: MessageStatus.delivered,
      isGreeting: true,
    );
  }
}
