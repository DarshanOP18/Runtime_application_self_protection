import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'rasp/rasp_check_model.dart';
import 'rasp/rasp_service.dart';
import 'screens/auth_gate.dart';
import 'screens/blocked_screen.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF14B8A6);
    const scaffold = Color(0xFF09111F);

    return MaterialApp(
      title: 'RASP App',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: seed,
          brightness: Brightness.dark,
          surface: const Color(0xFF121A2A),
        ),
        scaffoldBackgroundColor: scaffold,
        appBarTheme: const AppBarTheme(
          centerTitle: false,
          elevation: 0,
          backgroundColor: Colors.transparent,
          foregroundColor: Colors.white,
        ),
        cardTheme: CardThemeData(
          color: const Color(0xFF121A2A),
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF10192A),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(16),
            borderSide: BorderSide.none,
          ),
        ),
        snackBarTheme: SnackBarThemeData(
          backgroundColor: const Color(0xFF121A2A),
          contentTextStyle: const TextStyle(color: Colors.white),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
          behavior: SnackBarBehavior.floating,
        ),
      ),
      home: const RaspGate(),
    );
  }
}

class RaspGate extends StatefulWidget {
  const RaspGate({super.key});

  @override
  State<RaspGate> createState() => _RaspGateState();
}

class _RaspGateState extends State<RaspGate> with WidgetsBindingObserver {
  Future<RaspCheckResult>? _checksFuture;
  static const _securityChannel = MethodChannel('com.example.rasp_app/security');

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _runChecks();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) {
      _securityChannel.invokeMethod('applyBackgroundBlur');
      _clearClipboard(); // Secure Clipboard Protection
    } else if (state == AppLifecycleState.resumed) {
      _securityChannel.invokeMethod('removeBackgroundBlur');
      _runChecks(); // Re-check security on resume
    }
  }

  Future<void> _clearClipboard() async {
    try {
      await Clipboard.setData(const ClipboardData(text: ""));
    } catch (e) {
      // Ignore
    }
  }

  void _runChecks() {
    setState(() {
      _checksFuture = RaspService.runChecks();
    });
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<RaspCheckResult>(
      future: _checksFuture,
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          );
        }

        if (snapshot.hasError) {
          return Scaffold(
            body: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Text(
                      'Unable to complete device security checks.',
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 16),
                    ElevatedButton(
                      onPressed: _runChecks,
                      child: const Text('Try Again'),
                    ),
                  ],
                ),
              ),
            ),
          );
        }

        final result = snapshot.data!;

        if (result.shouldShowDeception) {
          return _buildDeceptiveScreen();
        }

        if (result.shouldBlockApp) {
          return BlockedScreen(
            reason: result.threatSummary,
            onRetry: _runChecks,
          );
        }

        return const AuthGate();
      },
    );
  }

  Widget _buildDeceptiveScreen() {
    return Scaffold(
      appBar: AppBar(
        title: const Text('System Maintenance'),
        automaticallyImplyLeading: false,
      ),
      body: const Center(
        child: Padding(
          padding: EdgeInsets.all(32.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.settings_suggest, size: 64, color: Colors.blue),
              SizedBox(height: 24),
              Text(
                'Server under maintenance',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              ),
              SizedBox(height: 12),
              Text(
                'We are currently performing scheduled maintenance on our servers. Please try again later. Error code: 0x8004100',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.grey),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
