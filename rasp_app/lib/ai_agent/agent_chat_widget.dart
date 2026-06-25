import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'agent_chat_controller.dart';
import 'agent_chat_model.dart';
import 'agent_config.dart';

class AgentChatWidget extends StatefulWidget {
  final String deviceId;

  const AgentChatWidget({super.key, required this.deviceId});

  @override
  State<AgentChatWidget> createState() => _AgentChatWidgetState();
}

class _AgentChatWidgetState extends State<AgentChatWidget>
    with TickerProviderStateMixin {
  late final AgentChatController _controller;
  late final AnimationController _pulseController;
  late final AnimationController _bounceController;
  late final AnimationController _panelController;
  late final Animation<double> _bounceAnimation;
  late final Animation<double> _panelOpacity;
  late final Animation<Offset> _panelOffset;
  final ScrollController _scrollController = ScrollController();
  final TextEditingController _textController = TextEditingController();
  final FocusNode _focusNode = FocusNode();
  String? _lastNoticeShown;
  bool _wasOpen = false;
  int _lastMessageCount = 0;

  @override
  void initState() {
    super.initState();
    _controller = AgentChatController();
    _controller.addListener(_handleControllerUpdate);

    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _bounceController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _bounceAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 1.0, end: 1.05)
            .chain(CurveTween(curve: Curves.easeInOut)),
        weight: 50,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 1.05, end: 1.0)
            .chain(CurveTween(curve: Curves.easeInOut)),
        weight: 50,
      ),
    ]).animate(_bounceController);

    _panelController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );

    final curvedPanel = CurvedAnimation(
      parent: _panelController,
      curve: Curves.easeOutCubic,
      reverseCurve: Curves.easeInCubic,
    );
    _panelOpacity = curvedPanel;
    _panelOffset = Tween<Offset>(
      begin: const Offset(0, 1),
      end: Offset.zero,
    ).animate(curvedPanel);

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        _controller.initialize(widget.deviceId);
      }
    });
  }

  @override
  void dispose() {
    _controller.removeListener(_handleControllerUpdate);
    _controller.dispose();
    _pulseController.dispose();
    _bounceController.dispose();
    _panelController.dispose();
    _scrollController.dispose();
    _textController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _handleControllerUpdate() {
    if (_controller.isOpen != _wasOpen) {
      _wasOpen = _controller.isOpen;
      if (_controller.isOpen) {
        _panelController.forward();
      } else {
        _panelController.reverse();
      }
    }

    if (_controller.lastNotice != null &&
        _controller.lastNotice != _lastNoticeShown) {
      _lastNoticeShown = _controller.lastNotice;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(_controller.lastNotice!),
          behavior: SnackBarBehavior.floating,
        ),
      );
      _controller.clearNotice();
    }

    if (_controller.messages.length != _lastMessageCount) {
      _lastMessageCount = _controller.messages.length;
      WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToBottom());
    }
  }

  void _showTapNotice() {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text("Hi-fi! I'm your live bot."),
        duration: Duration(seconds: 2),
      ),
    );
  }

  void _scrollToBottom() {
    if (!_scrollController.hasClients) {
      return;
    }

    _scrollController.animateTo(
      _scrollController.position.maxScrollExtent + 120,
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeOut,
    );
  }

  Future<void> _handleSend() async {
    final text = _textController.text;
    if (text.trim().isEmpty || _controller.isBotTyping) {
      return;
    }

    _textController.clear();
    _focusNode.requestFocus();
    await _controller.sendMessage(text);
  }

  Future<void> _handleRetry(ChatMessage message) async {
    if (_controller.lastFailedMessage != null) {
      await _controller.sendMessage(_controller.lastFailedMessage!);
      return;
    }

    await _controller.checkBackendHealth();
    if (_controller.isBackendOnline) {
      await _controller.sendMessage(message.text);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<AgentChatController>.value(
      value: _controller,
      child: Positioned.fill(
        child: Consumer<AgentChatController>(
          builder: (context, controller, _) {
            final media = MediaQuery.of(context);
            final width = media.size.width;
            final height = media.size.height;
            final safeBottom = media.padding.bottom + 20.0;
            final panelWidth = (width * 0.92).clamp(0.0, 420.0).toDouble();
            final panelHeight = height * 0.72;
            final showPanel = controller.isOpen || _panelController.isAnimating;

            return Stack(
              children: [
                if (showPanel)
                  Positioned(
                    right: 20,
                    bottom: safeBottom + 84,
                    child: FadeTransition(
                      opacity: _panelOpacity,
                      child: SlideTransition(
                        position: _panelOffset,
                        child: _ChatPanel(
                          width: panelWidth,
                          height: panelHeight,
                          controller: controller,
                          scrollController: _scrollController,
                          focusNode: _focusNode,
                          textController: _textController,
                          onClose: controller.closeChat,
                          onSend: _handleSend,
                          onQuickAction: (action) =>
                              _controller.sendQuickAction(action),
                          onRetry: _handleRetry,
                          onMessageTap: (message) {
                            if (message.suggestedQuestions.isNotEmpty) {
                              _controller.sendQuickAction(
                                message.suggestedQuestions.first,
                              );
                            }
                          },
                        ),
                      ),
                    ),
                  ),
                Positioned(
                  right: 20,
                  bottom: safeBottom,
                  child: ScaleTransition(
                    scale: _bounceAnimation,
                    child: AnimatedBuilder(
                      animation: _pulseController,
                      builder: (_, child) {
                        return _BotButton(
                          isOnline: controller.isBackendOnline,
                          pulseValue: _pulseController.value,
                          onTap: () {
                            _showTapNotice();
                            controller.toggleChat();
                          },
                        );
                      },
                    ),
                  ),
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}

class _BotButton extends StatelessWidget {
  final bool isOnline;
  final double pulseValue;
  final VoidCallback onTap;

  const _BotButton({
    required this.isOnline,
    required this.pulseValue,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final accent = isOnline ? const Color(0xFF14B8A6) : const Color(0xFF64748B);
    final glowOpacity = isOnline ? 0.22 * pulseValue : 0.12 * pulseValue;
    final glowShadowColor = Color.fromRGBO(
      accent.red,
      accent.green,
      accent.blue,
      glowOpacity,
    );

    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 220),
        width: 68,
        height: 68,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          boxShadow: [
            BoxShadow(
              color: glowShadowColor,
              blurRadius: 18 + (pulseValue * 10),
              spreadRadius: 1 + (pulseValue * 1.2),
            ),
          ],
        ),
        child: Stack(
          alignment: Alignment.center,
          children: [
            Container(
              width: 68,
              height: 68,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: const LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    Color(0xFF162131),
                    Color(0xFF0B1320),
                  ],
                ),
                border: Border.all(
                  color: accent.withOpacity(0.35),
                  width: 1.2,
                ),
              ),
            ),
            ClipOval(
              child: Image.asset(
                AgentConfig.botAvatar,
                width: 44,
                height: 44,
                fit: BoxFit.cover,
                errorBuilder: (_, _, _) {
                  return const CircleAvatar(
                    radius: 22,
                    backgroundColor: Color(0xFF1E2A3A),
                    child: Text('🤖', style: TextStyle(fontSize: 22)),
                  );
                },
              ),
            ),
            Positioned(
              right: 9,
              bottom: 9,
              child: Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  color: isOnline ? const Color(0xFF22C55E) : const Color(0xFF94A3B8),
                  shape: BoxShape.circle,
                  border: Border.all(color: const Color(0xFF0B1320), width: 2),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ChatPanel extends StatelessWidget {
  final double width;
  final double height;
  final AgentChatController controller;
  final ScrollController scrollController;
  final FocusNode focusNode;
  final TextEditingController textController;
  final VoidCallback onClose;
  final Future<void> Function() onSend;
  final Future<void> Function(String action) onQuickAction;
  final Future<void> Function(ChatMessage message) onRetry;
  final ValueChanged<ChatMessage> onMessageTap;

  const _ChatPanel({
    required this.width,
    required this.height,
    required this.controller,
    required this.scrollController,
    required this.focusNode,
    required this.textController,
    required this.onClose,
    required this.onSend,
    required this.onQuickAction,
    required this.onRetry,
    required this.onMessageTap,
  });

  @override
  Widget build(BuildContext context) {
    final canSend =
        textController.text.trim().isNotEmpty && !controller.isBotTyping;

    return Material(
      color: const Color(0xFF0D0D1A),
      elevation: 24,
      shadowColor: Colors.black54,
      borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
      child: Container(
        width: width,
        height: height,
        decoration: BoxDecoration(
          color: const Color(0xFF0D0D1A),
          borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
          border: Border.all(color: Colors.white12),
        ),
        child: Column(
          children: [
            _ChatHeader(controller: controller, onClose: onClose),
            Expanded(
              child: ListView.builder(
                controller: scrollController,
                padding: const EdgeInsets.fromLTRB(14, 14, 14, 8),
                itemCount: controller.messages.length,
                itemBuilder: (context, index) {
                  final message = controller.messages[index];
                  return _MessageTile(
                    message: message,
                    onRetry: () => onRetry(message),
                    onSuggestionTap: onQuickAction,
                    onMessageTap: onMessageTap,
                  );
                },
              ),
            ),
            _QuickActionsBar(
              quickActions: AgentConfig.quickActions,
              onQuickAction: onQuickAction,
            ),
            const SizedBox(height: 8),
            _InputBar(
              controller: textController,
              focusNode: focusNode,
              canSend: canSend,
              isTyping: controller.isBotTyping,
              onSend: onSend,
            ),
          ],
        ),
      ),
    );
  }
}

class _ChatHeader extends StatelessWidget {
  final AgentChatController controller;
  final VoidCallback onClose;

  const _ChatHeader({
    required this.controller,
    required this.onClose,
  });

  @override
  Widget build(BuildContext context) {
    final onlineColor =
        controller.isBackendOnline ? const Color(0xFF00FF88) : const Color(0xFFFF4444);

    return Container(
      padding: const EdgeInsets.fromLTRB(16, 14, 10, 14),
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A2E),
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _MiniAvatar(size: 36),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  AgentConfig.botName,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  AgentConfig.botTagline,
                  style: const TextStyle(
                    color: Color(0xFF8899AA),
                    fontSize: 12,
                  ),
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        color: onlineColor,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      controller.isBackendOnline ? 'Online' : 'Offline',
                      style: TextStyle(
                        color: onlineColor,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: onClose,
            icon: const Icon(Icons.close, color: Colors.white70),
            tooltip: 'Close',
          ),
        ],
      ),
    );
  }
}

class _MessageTile extends StatelessWidget {
  final ChatMessage message;
  final VoidCallback onRetry;
  final Future<void> Function(String action) onSuggestionTap;
  final ValueChanged<ChatMessage> onMessageTap;

  const _MessageTile({
    required this.message,
    required this.onRetry,
    required this.onSuggestionTap,
    required this.onMessageTap,
  });

  @override
  Widget build(BuildContext context) {
    if (message.isTypingIndicator) {
      return const Padding(
        padding: EdgeInsets.only(bottom: 10),
        child: _TypingDotsIndicator(),
      );
    }

    if (message.sender == MessageSender.system) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: Center(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: Colors.white10,
              borderRadius: BorderRadius.circular(16),
            ),
            child: Text(
              message.text,
              style: const TextStyle(
                color: Color(0xFF8899AA),
                fontSize: 11,
              ),
            ),
          ),
        ),
      );
    }

    final isBot = message.sender == MessageSender.bot;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: GestureDetector(
        onTap: () => onMessageTap(message),
        child: Row(
          mainAxisAlignment:
              isBot ? MainAxisAlignment.start : MainAxisAlignment.end,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (isBot) const _MiniAvatar(size: 24),
            if (isBot) const SizedBox(width: 8),
            Flexible(
              child: Column(
                crossAxisAlignment: isBot
                    ? CrossAxisAlignment.start
                    : CrossAxisAlignment.end,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 14,
                      vertical: 12,
                    ),
                    decoration: BoxDecoration(
                      color: isBot
                          ? const Color(0xFF1E2A3A)
                          : const Color(0xFF00517A),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: isBot ? Colors.white10 : Colors.white12,
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          message.text,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                            height: 1.4,
                          ),
                        ),
                        if (message.status == MessageStatus.error) ...[
                          const SizedBox(height: 10),
                          TextButton.icon(
                            onPressed: onRetry,
                            style: TextButton.styleFrom(
                              foregroundColor: const Color(0xFF00D4FF),
                              padding: EdgeInsets.zero,
                              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                            ),
                            icon: const Icon(Icons.refresh, size: 16),
                            label: const Text('Retry'),
                          ),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: 4),
                  Padding(
                    padding: EdgeInsets.only(
                      left: isBot ? 6 : 0,
                      right: isBot ? 0 : 6,
                    ),
                    child: Text(
                      _formatTimestamp(message.timestamp),
                      style: const TextStyle(
                        color: Color(0xFF8899AA),
                        fontSize: 10,
                      ),
                    ),
                  ),
                  if (isBot && message.suggestedQuestions.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: message.suggestedQuestions
                          .map(
                            (question) => ActionChip(
                              label: Text(question),
                              onPressed: () => onSuggestionTap(question),
                              labelStyle: const TextStyle(
                                color: Colors.white,
                                fontSize: 11,
                              ),
                              backgroundColor: const Color(0xFF1A1A2E),
                              side: const BorderSide(color: Colors.white12),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(18),
                              ),
                            ),
                          )
                          .toList(),
                    ),
                  ],
                ],
              ),
            ),
            if (!isBot) const SizedBox(width: 8),
          ],
        ),
      ),
    );
  }

  String _formatTimestamp(DateTime timestamp) {
    final local = timestamp.toLocal();
    final hour = local.hour.toString().padLeft(2, '0');
    final minute = local.minute.toString().padLeft(2, '0');
    return '$hour:$minute';
  }
}

class _QuickActionsBar extends StatelessWidget {
  final List<String> quickActions;
  final Future<void> Function(String action) onQuickAction;

  const _QuickActionsBar({
    required this.quickActions,
    required this.onQuickAction,
  });

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: 46,
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(horizontal: 14),
        scrollDirection: Axis.horizontal,
        itemCount: quickActions.length,
        separatorBuilder: (_, child) => const SizedBox(width: 8),
        itemBuilder: (context, index) {
          final action = quickActions[index];
          return ActionChip(
            label: Text(action),
            onPressed: () => onQuickAction(action),
            labelStyle: const TextStyle(
              color: Colors.white,
              fontSize: 11,
            ),
            backgroundColor: const Color(0xFF1A1A2E),
            side: const BorderSide(color: Colors.white12),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(18),
            ),
          );
        },
      ),
    );
  }
}

class _InputBar extends StatefulWidget {
  final TextEditingController controller;
  final FocusNode focusNode;
  final bool canSend;
  final bool isTyping;
  final Future<void> Function() onSend;

  const _InputBar({
    required this.controller,
    required this.focusNode,
    required this.canSend,
    required this.isTyping,
    required this.onSend,
  });

  @override
  State<_InputBar> createState() => _InputBarState();
}

class _InputBarState extends State<_InputBar> {
  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onTextChanged);
  }

  @override
  void didUpdateWidget(covariant _InputBar oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_onTextChanged);
      widget.controller.addListener(_onTextChanged);
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onTextChanged);
    super.dispose();
  }

  void _onTextChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final canSend =
        widget.controller.text.trim().isNotEmpty && !widget.isTyping;

    return Container(
      padding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: widget.controller,
              focusNode: widget.focusNode,
              enabled: !widget.isTyping,
              onSubmitted: (_) {
                if (canSend) {
                  widget.onSend();
                }
              },
              style: const TextStyle(color: Colors.white, fontSize: 14),
              decoration: InputDecoration(
                hintText: 'Ask about security...',
                hintStyle: const TextStyle(color: Color(0xFF8899AA)),
                filled: true,
                fillColor: const Color(0xFF1A1A2E),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 14,
                ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(20),
                  borderSide: BorderSide.none,
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(20),
                  borderSide: const BorderSide(color: Colors.white12),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(20),
                  borderSide: const BorderSide(color: Color(0xFF00D4FF)),
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),
          SizedBox(
            width: 48,
            height: 48,
            child: Material(
              color: canSend ? const Color(0xFF00D4FF) : Colors.white24,
              shape: const CircleBorder(),
              child: InkWell(
                customBorder: const CircleBorder(),
                onTap: canSend ? widget.onSend : null,
                child: const Icon(
                  Icons.arrow_upward_rounded,
                  color: Colors.white,
                  size: 22,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _MiniAvatar extends StatelessWidget {
  final double size;

  const _MiniAvatar({required this.size});

  @override
  Widget build(BuildContext context) {
    return ClipOval(
      child: Image.asset(
        AgentConfig.botAvatar,
        width: size,
        height: size,
        fit: BoxFit.cover,
        errorBuilder: (_, _, _) {
          return CircleAvatar(
            radius: size / 2,
            backgroundColor: const Color(0xFF1E2A3A),
            child: Text(
              '🤖',
              style: TextStyle(fontSize: size * 0.6),
            ),
          );
        },
      ),
    );
  }
}

class _TypingDotsIndicator extends StatefulWidget {
  const _TypingDotsIndicator();

  @override
  State<_TypingDotsIndicator> createState() => _TypingDotsIndicatorState();
}

class _TypingDotsIndicatorState extends State<_TypingDotsIndicator>
    with TickerProviderStateMixin {
  late final AnimationController _dot1Controller;
  late final AnimationController _dot2Controller;
  late final AnimationController _dot3Controller;
  late final Animation<double> _dot1;
  late final Animation<double> _dot2;
  late final Animation<double> _dot3;

  @override
  void initState() {
    super.initState();
    _dot1Controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    )..repeat(reverse: true);
    _dot2Controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    );
    _dot3Controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    );

    _dot1 = _buildDotAnimation(_dot1Controller);
    _dot2 = _buildDotAnimation(_dot2Controller);
    _dot3 = _buildDotAnimation(_dot3Controller);
    _startStaggered();
  }

  Animation<double> _buildDotAnimation(AnimationController controller) {
    final animation = Tween<double>(begin: 0, end: -6).animate(
      CurvedAnimation(parent: controller, curve: Curves.easeInOut),
    );

    return animation;
  }

  void _startStaggered() {
    _dot2Controller.value = 0.0;
    _dot3Controller.value = 0.0;
    Future<void>.delayed(const Duration(milliseconds: 150), () {
      if (mounted) _dot2Controller.repeat(reverse: true);
    });
    Future<void>.delayed(const Duration(milliseconds: 300), () {
      if (mounted) _dot3Controller.repeat(reverse: true);
    });
  }

  @override
  void dispose() {
    _dot1Controller.dispose();
    _dot2Controller.dispose();
    _dot3Controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Align(
        alignment: Alignment.centerLeft,
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const _MiniAvatar(size: 24),
            const SizedBox(width: 8),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              decoration: BoxDecoration(
                color: const Color(0xFF1E2A3A),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: Colors.white10),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  AnimatedBuilder(
                    animation: _dot1,
                    builder: (_, child) => Transform.translate(
                      offset: Offset(0, _dot1.value),
                      child: child,
                    ),
                    child: _buildDot(),
                  ),
                  const SizedBox(width: 6),
                  AnimatedBuilder(
                    animation: _dot2,
                    builder: (_, child) => Transform.translate(
                      offset: Offset(0, _dot2.value),
                      child: child,
                    ),
                    child: _buildDot(),
                  ),
                  const SizedBox(width: 6),
                  AnimatedBuilder(
                    animation: _dot3,
                    builder: (_, child) => Transform.translate(
                      offset: Offset(0, _dot3.value),
                      child: child,
                    ),
                    child: _buildDot(),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDot() {
    return Container(
      width: 8,
      height: 8,
      decoration: const BoxDecoration(
        color: Color(0xFF00D4FF),
        shape: BoxShape.circle,
      ),
    );
  }
}
