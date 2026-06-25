import 'package:flutter/material.dart';

import '../rasp/rasp_check_model.dart';
import '../widgets/security_status_card.dart';

class HomeScreen extends StatelessWidget {
  final RaspCheckResult result;
  final VoidCallback onRefresh;

  const HomeScreen({super.key, required this.result, required this.onRefresh});

  @override
  Widget build(BuildContext context) {
    final hasWarnings = result.isThreatDetected;
    final accent = hasWarnings ? const Color(0xFFF97316) : const Color(0xFF14B8A6);
    final headline = hasWarnings ? 'Security attention required' : 'Device protected';
    final subline = hasWarnings
        ? 'A few indicators need your review.'
        : 'Current checks look stable and clean.';
    final surface = const Color(0xFF0F1726);

    return Scaffold(
      backgroundColor: const Color(0xFF09111F),
      appBar: AppBar(
        title: const Text('RASP Security Center'),
        actions: [
          IconButton(
            onPressed: onRefresh,
            icon: const Icon(Icons.refresh_rounded),
            tooltip: 'Refresh scan',
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF0B1220), Color(0xFF09111F)],
          ),
        ),
        child: SafeArea(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(18, 12, 18, 24),
            children: [
              _HeroPanel(
                accent: accent,
                surface: surface,
                headline: headline,
                subline: subline,
                hasWarnings: hasWarnings,
                onRefresh: onRefresh,
              ),
              const SizedBox(height: 16),
              _OverviewRow(result: result),
              const SizedBox(height: 16),
              _SectionTitle(
                title: 'Core checks',
                subtitle: 'Primary device and app integrity signals.',
              ),
              const SizedBox(height: 8),
              SecurityStatusCard(
                label: 'Root / Jailbreak',
                isThreat: result.isRooted,
                icon: Icons.phonelink_lock_rounded,
              ),
              SecurityStatusCard(
                label: 'Emulator',
                isThreat: result.isEmulator,
                icon: Icons.devices_other_rounded,
              ),
              SecurityStatusCard(
                label: 'Debug Mode',
                isThreat: result.isDebugging,
                icon: Icons.bug_report_outlined,
              ),
              SecurityStatusCard(
                label: 'App Tamper',
                isThreat: result.isTampered,
                icon: Icons.verified_user_outlined,
              ),
              SecurityStatusCard(
                label: 'Screenshot Blocking',
                isThreat: !result.screenshotBlockingEnabled,
                icon: Icons.screenshot_monitor_outlined,
              ),
              const SizedBox(height: 14),
              _SectionTitle(
                title: 'Advanced layers',
                subtitle: 'Extra signals used for stronger protection.',
              ),
              const SizedBox(height: 8),
              SecurityStatusCard(
                label: 'Frida Framework',
                isThreat: result.isFridaDetected,
                icon: Icons.memory_rounded,
              ),
              SecurityStatusCard(
                label: 'VPN Connection',
                isThreat: result.isVpnActive,
                icon: Icons.vpn_lock_rounded,
              ),
              SecurityStatusCard(
                label: 'App Repackaging',
                isThreat: result.isRepackaged,
                icon: Icons.unarchive_outlined,
              ),
              SecurityStatusCard(
                label: 'RE Tools Active',
                isThreat: result.hasReverseEngineeringTools,
                icon: Icons.code_rounded,
              ),
              SecurityStatusCard(
                label: 'SSL / MITM Attack',
                isThreat: result.isMitmDetected,
                icon: Icons.lock_open_rounded,
              ),
              SecurityStatusCard(
                label: 'Overlay Attack',
                isThreat: result.isOverlayDetected,
                icon: Icons.layers_outlined,
              ),
              SecurityStatusCard(
                label: 'Accessibility Abuse',
                isThreat: result.isAccessibilityAbused,
                icon: Icons.accessibility_new_rounded,
              ),
              SecurityStatusCard(
                label: 'Device Integrity',
                subtitle: result.isDeviceRisk
                    ? result.deviceRiskReason
                    : 'Hardware and settings look stable',
                isThreat: result.isDeviceRisk,
                icon: Icons.fingerprint_rounded,
              ),
              const SizedBox(height: 14),
              _SectionTitle(
                title: 'Enterprise layers',
                subtitle: 'Controls that matter in a managed deployment.',
              ),
              const SizedBox(height: 8),
              SecurityStatusCard(
                label: 'Dual App / Cloning',
                isThreat: result.isCloneDetected,
                icon: Icons.copy_rounded,
              ),
              SecurityStatusCard(
                label: 'Device Binding',
                subtitle: result.isDeviceBindingFailed
                    ? 'Hardware key tampered'
                    : 'Hardware bound to device',
                isThreat: result.isDeviceBindingFailed,
                icon: Icons.link_rounded,
              ),
              SecurityStatusCard(
                label: 'Offline Compliance',
                subtitle: result.isOfflineExceeded
                    ? 'Offline limit exceeded'
                    : 'Usage within limits',
                isThreat: result.isOfflineExceeded,
                icon: Icons.signal_wifi_off_rounded,
              ),
              SecurityStatusCard(
                label: 'IP Reputation & Geo',
                subtitle: result.isHighRiskIp
                    ? 'Blocked country or VPN IP'
                    : 'Connection looks clean',
                isThreat: result.isHighRiskIp,
                icon: Icons.public_rounded,
              ),
              const SizedBox(height: 10),
              if (hasWarnings && !result.isBlockingEnforced)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(
                    result.threatSummary,
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.62),
                      height: 1.4,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _HeroPanel extends StatelessWidget {
  final Color accent;
  final Color surface;
  final String headline;
  final String subline;
  final bool hasWarnings;
  final VoidCallback onRefresh;

  const _HeroPanel({
    required this.accent,
    required this.surface,
    required this.headline,
    required this.subline,
    required this.hasWarnings,
    required this.onRefresh,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            surface,
            surface.withOpacity(0.94),
          ],
        ),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: accent.withOpacity(0.18)),
        boxShadow: [
          BoxShadow(
            color: accent.withOpacity(0.09),
            blurRadius: 28,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [accent, accent.withOpacity(0.7)],
                  ),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Icon(
                  hasWarnings ? Icons.warning_amber_rounded : Icons.shield_rounded,
                  color: Colors.white,
                ),
              ),
              const Spacer(),
              TextButton.icon(
                onPressed: onRefresh,
                icon: const Icon(Icons.refresh_rounded, size: 18),
                label: const Text('Rescan'),
                style: TextButton.styleFrom(
                  foregroundColor: Colors.white,
                  backgroundColor: Colors.white.withOpacity(0.06),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          Text(
            headline,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 22,
              fontWeight: FontWeight.w700,
              letterSpacing: -0.4,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            subline,
            style: TextStyle(
              color: Colors.white.withOpacity(0.68),
              height: 1.4,
            ),
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              _MiniPill(
                label: hasWarnings ? 'Review needed' : 'All clear',
                accent: accent,
              ),
              _MiniPill(
                label: resultStateLabel(),
                accent: Colors.white,
                muted: true,
              ),
            ],
          ),
        ],
      ),
    );
  }

  String resultStateLabel() {
    return hasWarnings ? 'Risk indicators active' : 'Stable scan state';
  }
}

class _OverviewRow extends StatelessWidget {
  final RaspCheckResult result;

  const _OverviewRow({required this.result});

  @override
  Widget build(BuildContext context) {
    final riskCount = <bool>[
      result.isRooted,
      result.isEmulator,
      result.isDebugging,
      result.isTampered,
      result.isFridaDetected,
      result.isVpnActive,
      result.isMitmDetected,
      result.isRepackaged,
      result.hasReverseEngineeringTools,
      result.isOverlayDetected,
      result.isAccessibilityAbused,
      result.isDeviceRisk,
      result.isCloneDetected,
      result.isDeviceBindingFailed,
      result.isHighRiskIp,
      result.isOfflineExceeded,
    ].where((item) => item).length;

    return Row(
      children: [
        Expanded(
          child: _InfoCard(
            title: 'Threats',
            value: '$riskCount',
            icon: Icons.report_problem_rounded,
            accent: const Color(0xFFF97316),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _InfoCard(
            title: 'Blocks',
            value: result.isBlockingEnforced ? 'On' : 'Off',
            icon: Icons.shield_rounded,
            accent: const Color(0xFF14B8A6),
          ),
        ),
      ],
    );
  }
}

class _InfoCard extends StatelessWidget {
  final String title;
  final String value;
  final IconData icon;
  final Color accent;

  const _InfoCard({
    required this.title,
    required this.value,
    required this.icon,
    required this.accent,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF101B23),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: accent.withOpacity(0.18)),
      ),
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: accent.withOpacity(0.12),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Icon(icon, color: accent, size: 20),
          ),
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                value,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                title,
                style: TextStyle(
                  color: Colors.white.withOpacity(0.55),
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _SectionTitle extends StatelessWidget {
  final String title;
  final String subtitle;

  const _SectionTitle({
    required this.title,
    required this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title.toUpperCase(),
          style: TextStyle(
            color: Colors.white.withOpacity(0.72),
            fontSize: 11,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.4,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          subtitle,
          style: TextStyle(
            color: Colors.white.withOpacity(0.42),
            fontSize: 12,
            height: 1.3,
          ),
        ),
      ],
    );
  }
}

class _MiniPill extends StatelessWidget {
  final String label;
  final Color accent;
  final bool muted;

  const _MiniPill({
    required this.label,
    required this.accent,
    this.muted = false,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: muted ? Colors.white.withOpacity(0.05) : accent.withOpacity(0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
          color: muted ? Colors.white.withOpacity(0.1) : accent.withOpacity(0.18),
        ),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: muted ? Colors.white.withOpacity(0.65) : accent,
          fontSize: 11,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}
