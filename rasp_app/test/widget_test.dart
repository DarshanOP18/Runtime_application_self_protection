import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rasp_app/main.dart';
import 'package:rasp_app/rasp/rasp_check_model.dart';

void main() {
  testWidgets('RaspGate shows auth flow when checks pass', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RaspGate(
          checkRunner: () async => const RaspCheckResult(
            isRooted: false,
            isEmulator: false,
            isDebugging: false,
            isTampered: false,
            isBlockingEnforced: true,
          ),
          authGateBuilder: (_) => const Text('auth-ready'),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('auth-ready'), findsOneWidget);
  });

  testWidgets('RaspGate blocks when enforced checks find a threat', (WidgetTester tester) async {
    var retryCount = 0;

    await tester.pumpWidget(
      MaterialApp(
        home: RaspGate(
          checkRunner: () async => const RaspCheckResult(
            isRooted: true,
            isEmulator: false,
            isDebugging: false,
            isTampered: false,
            isBlockingEnforced: true,
          ),
          blockedBuilder: (reason, onRetry) => TextButton(
            onPressed: () {
              retryCount++;
              onRetry();
            },
            child: Text(reason),
          ),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('Rooted/Jailbroken Device'), findsOneWidget);

    await tester.tap(find.text('Rooted/Jailbroken Device'));
    await tester.pump();

    expect(retryCount, 1);
  });
}
