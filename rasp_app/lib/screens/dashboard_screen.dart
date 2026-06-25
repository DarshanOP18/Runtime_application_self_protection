// ==================== dashboard_screen.dart ====================
// Role-aware post-login dashboard with:
//   • User profile card with role badge
//   • Permission-gated feature tiles
//   • New User: limited view + "Verify Account" button
//   • Existing User: full dashboard
//   • Admin: user management panel + audit log viewer
//   • Navigation to RASP Security Dashboard (HomeScreen)
//   • Logout functionality

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:rasp_app/ai_agent/agent_chat_widget.dart';
import '../database/user_repository.dart';
import '../models/user_model.dart';
import '../rasp/rasp_service.dart';
import 'home_screen.dart';
import 'login_screen.dart';

class DashboardScreen extends StatefulWidget {
  final UserModel user;

  const DashboardScreen({super.key, required this.user});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with SingleTickerProviderStateMixin {
  late UserModel _user;
  final _userRepo = UserRepository();
  final _secureStorage = const FlutterSecureStorage();

  bool _isVerifying = false;
  bool _isLoggingOut = false;

  late AnimationController _animController;
  late Animation<double> _fadeAnim;

  static const String _sessionKey = 'active_session_token';

  @override
  void initState() {
    super.initState();
    _user = widget.user;
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 700),
    );
    _fadeAnim = CurvedAnimation(
      parent: _animController,
      curve: Curves.easeOut,
    );
    _animController.forward();
  }

  @override
  void dispose() {
    _animController.dispose();
    super.dispose();
  }

  // ─────────────── Actions ───────────────

  Future<void> _handleVerify() async {
    if (_user.id == null) return;
    setState(() => _isVerifying = true);

    try {
      final bool success = await _userRepo.verifyAndUpgradeUser(_user.id!);
      if (success && mounted) {
        // Re-fetch user to get updated role & permissions
        final UserModel? updated = await _userRepo.getUserWithRole(_user.id!);
        final perms = await _userRepo.getAllPermissionsForUser(_user.id!);
        if (updated != null) {
          setState(() {
            _user = updated.copyWith(
              sessionToken: _user.sessionToken,
              permissions: perms,
            );
          });
          _showSnackbar('Account verified! You now have existing_user access.',
              const Color(0xFF10B981));
        }
      }
    } catch (e) {
      _showSnackbar('Verification failed. Please try again.', Colors.red);
    } finally {
      if (mounted) setState(() => _isVerifying = false);
    }
  }

  Future<void> _handleLogout() async {
    setState(() => _isLoggingOut = true);

    try {
      if (_user.sessionToken != null) {
        await _userRepo.logoutUser(_user.sessionToken!);
        await _secureStorage.delete(key: _sessionKey);
      }
    } catch (_) {
      // Always logout even on error
    }

    if (mounted) {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const LoginScreen()),
        (route) => false,
      );
    }
  }

  Future<void> _navigateToSecurityDashboard() async {
    // Run RASP checks and show results
    try {
      final result = await RaspService.runChecks();
      if (mounted) {
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => HomeScreen(
              result: result,
              onRefresh: () {
                Navigator.of(context).pop();
                _navigateToSecurityDashboard();
              },
            ),
          ),
        );
      }
    } catch (e) {
      _showSnackbar('Failed to run security checks.', Colors.red);
    }
  }

  void _showSnackbar(String msg, Color color) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: color,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    );
  }

  // ─────────────── Build ───────────────

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        Scaffold(
          backgroundColor: const Color(0xFF09111F),
          appBar: _buildAppBar(),
          body: FadeTransition(
            opacity: _fadeAnim,
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [Color(0xFF0B1220), Color(0xFF09111F)],
                ),
              ),
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(18, 14, 18, 32),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildHeroBanner(),
                    const SizedBox(height: 16),
                    _buildProfileCard(),
                    const SizedBox(height: 18),
                    _buildPermissionsSection(),
                    const SizedBox(height: 18),
                    _buildFeatureGrid(),
                    const SizedBox(height: 18),
                    if (_user.isNewUser) _buildVerificationBanner(),
                    if (_user.isAdmin) ...[
                      const SizedBox(height: 14),
                      _buildAdminPanel(),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
        AgentChatWidget(
          deviceId: _user.id?.toString() ?? 'guest_device',
        ),
      ],
    );
  }

  PreferredSizeWidget _buildAppBar() {
    return AppBar(
      backgroundColor: const Color(0xFF09111F),
      elevation: 0,
      automaticallyImplyLeading: false,
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF14B8A6), Color(0xFF2563EB)],
              ),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.shield_outlined,
                color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          const Text(
            'RASP Dashboard',
            style: TextStyle(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
      actions: [
        IconButton(
          onPressed: _isLoggingOut ? null : _handleLogout,
          icon: _isLoggingOut
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation(Colors.white54),
                  ),
                )
              : const Icon(Icons.logout, color: Colors.white54, size: 22),
          tooltip: 'Logout',
        ),
        const SizedBox(width: 8),
      ],
    );
  }

  Widget _buildHeroBanner() {
    final roleColor = _getRoleColor();

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            const Color(0xFF121A2A),
            const Color(0xFF0F1726),
          ],
        ),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: roleColor.withOpacity(0.16)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 54,
            height: 54,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [roleColor, roleColor.withOpacity(0.65)],
              ),
              borderRadius: BorderRadius.circular(18),
            ),
            child: const Icon(Icons.workspace_premium_rounded, color: Colors.white),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Welcome back, ${_user.username}',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 20,
                    fontWeight: FontWeight.w700,
                    letterSpacing: -0.3,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  'Your access is organized by role, permissions, and live security controls.',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.62),
                    height: 1.35,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ─────────────── Profile Card ───────────────

  Widget _buildProfileCard() {
    final roleColor = _getRoleColor();

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            const Color(0xFF111A2A),
            const Color(0xFF0E1523),
          ],
        ),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
        boxShadow: [
          BoxShadow(
            color: roleColor.withOpacity(0.12),
            blurRadius: 30,
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
                width: 58,
                height: 58,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: LinearGradient(
                    colors: [roleColor, roleColor.withOpacity(0.6)],
                  ),
                ),
                child: Center(
                  child: Text(
                    _user.username[0].toUpperCase(),
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 22,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _user.username,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 19,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      _user.email,
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.5),
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
              _buildRoleBadge(),
            ],
          ),
          const SizedBox(height: 18),
          Row(
            children: [
              _buildStat('Logins', _user.loginCount.toString()),
              _buildStatDivider(),
              _buildStat(
                  'Status',
                  _user.isVerified == 1 ? 'Verified' : 'Unverified'),
              _buildStatDivider(),
              _buildStat(
                  'Account', _user.isActive == 1 ? 'Active' : 'Disabled'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildRoleBadge() {
    final roleColor = _getRoleColor();
    final roleName = _user.roleName ?? 'unknown';
    final displayName = roleName.replaceAll('_', ' ').toUpperCase();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: roleColor.withOpacity(0.15),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: roleColor.withOpacity(0.3)),
      ),
      child: Text(
        displayName,
        style: TextStyle(
          color: roleColor,
          fontSize: 10,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.5,
        ),
      ),
    );
  }

  Widget _buildStat(String label, String value) {
    return Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            style: TextStyle(
              color: Colors.white.withOpacity(0.4),
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatDivider() {
    return Container(
      width: 1,
      height: 30,
      color: Colors.white.withOpacity(0.08),
    );
  }

  // ─────────────── Permissions ───────────────

  Widget _buildPermissionsSection() {
    final perms = _user.permissions;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: const Color(0xFF101B23),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'YOUR PERMISSIONS',
            style: TextStyle(
              color: Colors.white.withOpacity(0.42),
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.5,
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              if (perms.isEmpty)
                _buildPermChip('No permissions', false)
              else
                ...perms.map((p) => _buildPermChip(p, true)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPermChip(String name, bool active) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: active
            ? const Color(0xFF10B981).withOpacity(0.12)
            : const Color(0xFFEF4444).withOpacity(0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: active
              ? const Color(0xFF10B981).withOpacity(0.25)
              : const Color(0xFFEF4444).withOpacity(0.25),
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            active ? Icons.check_circle_outline : Icons.cancel_outlined,
            size: 14,
            color: active ? const Color(0xFF10B981) : const Color(0xFFEF4444),
          ),
          const SizedBox(width: 6),
          Text(
            name.toUpperCase(),
            style: TextStyle(
              color: active ? const Color(0xFF6EE7B7) : const Color(0xFFFCA5A5),
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }

  // ─────────────── Feature Grid ───────────────

  Widget _buildFeatureGrid() {
    final features = <_FeatureTile>[];

    // Security Dashboard — available to all
    features.add(_FeatureTile(
      icon: Icons.security,
      label: 'Security\nDashboard',
      color: const Color(0xFF3B82F6),
      onTap: _navigateToSecurityDashboard,
    ));

    // Profile — available to all
    features.add(_FeatureTile(
      icon: Icons.person_outline,
      label: 'My\nProfile',
      color: const Color(0xFF8B5CF6),
      onTap: () => _showSnackbar('Profile view coming soon!', const Color(0xFF8B5CF6)),
    ));

    // Write-gated features
    if (_user.permissions.contains('write')) {
      features.add(_FeatureTile(
        icon: Icons.edit_note,
        label: 'Create\nContent',
        color: const Color(0xFF10B981),
        onTap: () => _showSnackbar('Write access granted!', const Color(0xFF10B981)),
      ));
    }

    // Report viewing
    if (_user.permissions.contains('view_reports')) {
      features.add(_FeatureTile(
        icon: Icons.bar_chart,
        label: 'View\nReports',
        color: const Color(0xFFF59E0B),
        onTap: () => _showSnackbar('Reports access granted!', const Color(0xFFF59E0B)),
      ));
    }

    // Admin features
    if (_user.permissions.contains('manage_users')) {
      features.add(_FeatureTile(
        icon: Icons.admin_panel_settings,
        label: 'Manage\nUsers',
        color: const Color(0xFFEF4444),
        onTap: () => _showAdminUsersDialog(),
      ));
    }

    if (_user.permissions.contains('delete')) {
      features.add(_FeatureTile(
        icon: Icons.delete_sweep,
        label: 'Delete\nRecords',
        color: const Color(0xFFDC2626),
        onTap: () => _showSnackbar('Delete access granted!', const Color(0xFFDC2626)),
      ));
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'FEATURES',
          style: TextStyle(
            color: Colors.white.withOpacity(0.4),
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 1.5,
          ),
        ),
        const SizedBox(height: 10),
        GridView.extent(
          maxCrossAxisExtent: 180,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisSpacing: 12,
          mainAxisSpacing: 12,
          childAspectRatio: 1.1,
          children: features.map((f) => _buildFeatureTileWidget(f)).toList(),
        ),
      ],
    );
  }

  Widget _buildFeatureTileWidget(_FeatureTile tile) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: tile.onTap,
        borderRadius: BorderRadius.circular(20),
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: const Color(0xFF101B23),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: tile.color.withOpacity(0.16)),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: tile.color.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Icon(tile.icon, color: tile.color, size: 22),
              ),
              const SizedBox(height: 8),
              Text(
                tile.label,
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white.withOpacity(0.84),
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  height: 1.25,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ─────────────── Verification Banner (New Users) ───────────────

  Widget _buildVerificationBanner() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            const Color(0xFFF59E0B).withOpacity(0.12),
            const Color(0xFFF59E0B).withOpacity(0.04),
          ],
        ),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: const Color(0xFFF59E0B).withOpacity(0.2)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.warning_amber_rounded,
                  color: Color(0xFFF59E0B), size: 22),
              const SizedBox(width: 8),
              const Text(
                'Account Not Verified',
                style: TextStyle(
                  color: Color(0xFFFBBF24),
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'You currently have limited (read-only) access. '
            'Verify your account to unlock write permissions and full features.',
            style: TextStyle(
              color: Colors.white.withOpacity(0.5),
              fontSize: 13,
              height: 1.4,
            ),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _isVerifying ? null : _handleVerify,
              icon: _isVerifying
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor:
                            AlwaysStoppedAnimation<Color>(Colors.white),
                      ),
                    )
                  : const Icon(Icons.verified_outlined, size: 18),
              label: Text(_isVerifying ? 'Verifying...' : 'Verify My Account'),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFF59E0B),
                foregroundColor: Colors.black87,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
                padding: const EdgeInsets.symmetric(vertical: 12),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ─────────────── Admin Panel ───────────────

  Widget _buildAdminPanel() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'ADMIN PANEL',
          style: TextStyle(
            color: Colors.white.withOpacity(0.4),
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 1.5,
          ),
        ),
        const SizedBox(height: 10),
        _buildAdminTile(
          icon: Icons.people_outline,
          label: 'View All Users',
          subtitle: 'Manage roles and permissions',
          onTap: _showAdminUsersDialog,
        ),
        const SizedBox(height: 8),
        _buildAdminTile(
          icon: Icons.history,
          label: 'Audit Logs',
          subtitle: 'View security event history',
          onTap: _showAuditLogsDialog,
        ),
      ],
    );
  }

  Widget _buildAdminTile({
    required IconData icon,
    required String label,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: const Color(0xFF101B23),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
                color: const Color(0xFF8B5CF6).withOpacity(0.15)),
          ),
          child: Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF8B5CF6).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(icon,
                    color: const Color(0xFF8B5CF6), size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      label,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 14,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                    Text(
                      subtitle,
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.4),
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right,
                  color: Colors.white.withOpacity(0.3), size: 20),
            ],
          ),
        ),
      ),
    );
  }

  // ─────────────── Admin Dialogs ───────────────

  Future<void> _showAdminUsersDialog() async {
    final users = await _userRepo.getAllUsers();

    if (!mounted) return;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF161B22),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return DraggableScrollableSheet(
          expand: false,
          initialChildSize: 0.6,
          maxChildSize: 0.9,
          minChildSize: 0.3,
          builder: (_, scrollController) {
            return Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Center(
                    child: Container(
                      width: 40,
                      height: 4,
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'All Users (${users.length})',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Expanded(
                    child: ListView.separated(
                      controller: scrollController,
                      itemCount: users.length,
                      separatorBuilder: (_, __) => Divider(
                        color: Colors.white.withOpacity(0.06),
                        height: 1,
                      ),
                      itemBuilder: (_, i) {
                        final u = users[i];
                        final color = _getRoleColorByName(u.roleName);
                        return ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: CircleAvatar(
                            backgroundColor: color.withOpacity(0.15),
                            child: Text(
                              u.username[0].toUpperCase(),
                              style: TextStyle(
                                  color: color, fontWeight: FontWeight.bold),
                            ),
                          ),
                          title: Text(
                            u.username,
                            style: const TextStyle(
                                color: Colors.white, fontSize: 14),
                          ),
                          subtitle: Text(
                            '${u.email} • ${u.roleName ?? "unknown"}',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.4),
                              fontSize: 12,
                            ),
                          ),
                          trailing: Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 8, vertical: 3),
                            decoration: BoxDecoration(
                              color: u.isVerified == 1
                                  ? const Color(0xFF10B981).withOpacity(0.12)
                                  : const Color(0xFFF59E0B).withOpacity(0.12),
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: Text(
                              u.isVerified == 1 ? 'Verified' : 'Unverified',
                              style: TextStyle(
                                color: u.isVerified == 1
                                    ? const Color(0xFF10B981)
                                    : const Color(0xFFF59E0B),
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  Future<void> _showAuditLogsDialog() async {
    final logs = await _userRepo.getAuditLogs(limit: 100);

    if (!mounted) return;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF161B22),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return DraggableScrollableSheet(
          expand: false,
          initialChildSize: 0.6,
          maxChildSize: 0.9,
          minChildSize: 0.3,
          builder: (_, scrollController) {
            return Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Center(
                    child: Container(
                      width: 40,
                      height: 4,
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'Audit Logs (${logs.length})',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Expanded(
                    child: ListView.separated(
                      controller: scrollController,
                      itemCount: logs.length,
                      separatorBuilder: (_, __) => Divider(
                        color: Colors.white.withOpacity(0.06),
                        height: 1,
                      ),
                      itemBuilder: (_, i) {
                        final log = logs[i];
                        final action = log['action'] as String? ?? '';
                        final user = log['username'] as String? ?? 'system';
                        final details = log['details'] as String? ?? '';
                        final time = log['performed_at'] as String? ?? '';

                        Color actionColor;
                        switch (action) {
                          case 'LOGIN':
                            actionColor = const Color(0xFF10B981);
                            break;
                          case 'LOGOUT':
                            actionColor = const Color(0xFF6B7280);
                            break;
                          case 'REGISTER':
                            actionColor = const Color(0xFF3B82F6);
                            break;
                          case 'ROLE_UPGRADED':
                          case 'ROLE_CHANGED':
                            actionColor = const Color(0xFF8B5CF6);
                            break;
                          case 'PERMISSION_DENIED':
                          case 'LOGIN_FAILED':
                            actionColor = const Color(0xFFEF4444);
                            break;
                          default:
                            actionColor = const Color(0xFF6B7280);
                        }

                        return Padding(
                          padding: const EdgeInsets.symmetric(vertical: 8),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Container(
                                width: 6,
                                height: 6,
                                margin: const EdgeInsets.only(top: 6),
                                decoration: BoxDecoration(
                                  shape: BoxShape.circle,
                                  color: actionColor,
                                ),
                              ),
                              const SizedBox(width: 10),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment:
                                      CrossAxisAlignment.start,
                                  children: [
                                    Row(
                                      children: [
                                        Container(
                                          padding: const EdgeInsets.symmetric(
                                              horizontal: 6, vertical: 2),
                                          decoration: BoxDecoration(
                                            color: actionColor
                                                .withOpacity(0.12),
                                            borderRadius:
                                                BorderRadius.circular(4),
                                          ),
                                          child: Text(
                                            action,
                                            style: TextStyle(
                                              color: actionColor,
                                              fontSize: 10,
                                              fontWeight: FontWeight.w700,
                                            ),
                                          ),
                                        ),
                                        const SizedBox(width: 6),
                                        Text(
                                          user,
                                          style: TextStyle(
                                            color:
                                                Colors.white.withOpacity(0.6),
                                            fontSize: 12,
                                          ),
                                        ),
                                      ],
                                    ),
                                    if (details.isNotEmpty) ...[
                                      const SizedBox(height: 3),
                                      Text(
                                        details,
                                        style: TextStyle(
                                          color:
                                              Colors.white.withOpacity(0.35),
                                          fontSize: 11,
                                        ),
                                        maxLines: 2,
                                        overflow: TextOverflow.ellipsis,
                                      ),
                                    ],
                                    const SizedBox(height: 3),
                                    Text(
                                      _formatTimestamp(time),
                                      style: TextStyle(
                                        color:
                                            Colors.white.withOpacity(0.25),
                                        fontSize: 10,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        );
                      },
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  // ─────────────── Helpers ───────────────

  Color _getRoleColor() {
    return _getRoleColorByName(_user.roleName);
  }

  Color _getRoleColorByName(String? roleName) {
    switch (roleName) {
      case 'admin':
        return const Color(0xFF8B5CF6); // Purple
      case 'moderator':
        return const Color(0xFF3B82F6); // Blue
      case 'existing_user':
        return const Color(0xFF10B981); // Green
      case 'new_user':
        return const Color(0xFFF59E0B); // Amber
      default:
        return const Color(0xFF6B7280); // Grey
    }
  }

  String _formatTimestamp(String iso) {
    try {
      final dt = DateTime.parse(iso).toLocal();
      return '${dt.day}/${dt.month}/${dt.year} ${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
    } catch (_) {
      return iso;
    }
  }
}

// ─────────────── Feature Tile Data Class ───────────────

class _FeatureTile {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;

  const _FeatureTile({
    required this.icon,
    required this.label,
    required this.color,
    required this.onTap,
  });
}
