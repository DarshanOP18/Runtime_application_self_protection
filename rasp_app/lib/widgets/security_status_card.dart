import 'package:flutter/material.dart';

class SecurityStatusCard extends StatelessWidget {
  final String label;
  final String? subtitle;
  final bool isThreat;
  final IconData icon;

  const SecurityStatusCard({
    super.key,
    required this.label,
    this.subtitle,
    required this.isThreat,
    this.icon = Icons.security,
  });

  @override
  Widget build(BuildContext context) {
    final accentColor =
        isThreat ? const Color(0xFFF97316) : const Color(0xFF14B8A6);
    final surfaceColor =
        isThreat ? const Color(0xFF1D1620) : const Color(0xFF101B23);
    final borderColor = accentColor.withOpacity(0.24);
    final statusLabel = isThreat ? 'Risk' : 'Secure';

    return Card(
      elevation: 0,
      margin: const EdgeInsets.symmetric(vertical: 8),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: BorderSide(color: borderColor, width: 1),
      ),
      child: Container(
        decoration: BoxDecoration(
          color: surfaceColor,
          borderRadius: BorderRadius.circular(20),
        ),
        child: ListTile(
          contentPadding:
              const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          leading: Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: accentColor.withOpacity(0.12),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Icon(icon, color: accentColor, size: 22),
          ),
          title: Text(
            label,
            style: const TextStyle(
              fontWeight: FontWeight.w600,
              fontSize: 15,
              color: Colors.white,
            ),
          ),
          subtitle: Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text(
              subtitle ?? (isThreat ? 'Attention needed' : 'No issues found'),
              style: TextStyle(
                fontSize: 12,
                color: Colors.white.withOpacity(0.58),
              ),
            ),
          ),
          trailing: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: accentColor.withOpacity(0.12),
              borderRadius: BorderRadius.circular(999),
            ),
            child: Text(
              statusLabel.toUpperCase(),
              style: TextStyle(
                color: accentColor,
                fontWeight: FontWeight.w700,
                fontSize: 11,
                letterSpacing: 0.6,
              ),
            ),
          ),
        ),
      ),
    );
  }
}
