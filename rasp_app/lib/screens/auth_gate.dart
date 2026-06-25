// ==================== auth_gate.dart ====================
// Checks for an existing valid session token in the local database.
// If found → auto-login and navigate to DashboardScreen.
// If not found or expired → show LoginScreen.
//
// This widget sits between RaspGate and the app's feature screens,
// ensuring authentication is always enforced on launch.

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import '../database/user_repository.dart';
import '../models/user_model.dart';
import 'login_screen.dart';
import 'dashboard_screen.dart';

class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  final UserRepository _userRepo = UserRepository();
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  bool _isLoading = true;

  static const String _sessionKey = 'active_session_token';

  @override
  void initState() {
    super.initState();
    _checkExistingSession();
  }

  /// Attempt to resume an existing session from secure storage.
  Future<void> _checkExistingSession() async {
    try {
      final String? storedToken = await _secureStorage.read(key: _sessionKey);

      if (storedToken != null && storedToken.isNotEmpty) {
        // Validate the token against the database
        final UserModel? user =
            await _userRepo.getUserBySessionToken(storedToken);

        if (user != null && mounted) {
          // Valid session — navigate directly to dashboard
          Navigator.of(context).pushReplacement(
            MaterialPageRoute(
              builder: (_) => DashboardScreen(user: user),
            ),
          );
          return;
        } else {
          // Token was invalid or expired — clear it
          await _secureStorage.delete(key: _sessionKey);
        }
      }
    } catch (_) {
      // On any error, fall through to login screen
    }

    if (mounted) {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return Scaffold(
        backgroundColor: const Color(0xFF0D1117),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Animated shield icon
              TweenAnimationBuilder<double>(
                tween: Tween(begin: 0.0, end: 1.0),
                duration: const Duration(milliseconds: 800),
                builder: (context, value, child) {
                  return Opacity(
                    opacity: value,
                    child: Transform.scale(
                      scale: 0.5 + (value * 0.5),
                      child: child,
                    ),
                  );
                },
                child: Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: LinearGradient(
                      colors: [
                        const Color(0xFF6C63FF),
                        const Color(0xFF3B82F6),
                      ],
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFF6C63FF).withOpacity(0.4),
                        blurRadius: 30,
                        spreadRadius: 5,
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.shield_outlined,
                    color: Colors.white,
                    size: 48,
                  ),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Authenticating...',
                style: TextStyle(
                  color: Colors.white70,
                  fontSize: 16,
                  fontWeight: FontWeight.w500,
                  letterSpacing: 0.5,
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: 32,
                height: 32,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  valueColor: AlwaysStoppedAnimation<Color>(
                    const Color(0xFF6C63FF),
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    }

    return const LoginScreen();
  }
}
