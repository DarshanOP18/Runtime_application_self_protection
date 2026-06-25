// ==================== user_repository.dart ====================
// Data-access layer for all user-related operations.
// Every SQL query is parameterised (no string interpolation) to prevent
// SQL injection. All timestamps are stored as ISO 8601 UTC strings.

import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';
import 'database_helper.dart';
import '../models/user_model.dart';
import '../models/role_model.dart';

class UserRepository {
  final DatabaseHelper _dbHelper = DatabaseHelper();
  final _uuid = const Uuid();

  // ─────────────── Helpers ───────────────

  /// Hash a plaintext password using SHA-256. NEVER store raw passwords.
  String _hashPassword(String password) {
    return sha256.convert(utf8.encode(password)).toString();
  }

  /// Current UTC timestamp as ISO 8601 string.
  String _now() => DateTime.now().toUtc().toIso8601String();

  // ─────────────── Registration ───────────────

  /// Register a new user with the 'new_user' role (id=4).
  /// Returns the auto-generated user ID.
  ///
  /// Throws [Exception] if the username or email already exists
  /// (caught by UNIQUE constraint).
  Future<int> registerUser({
    required String username,
    required String email,
    required String password,
    required String contactNumber,
  }) async {
    final db = await _dbHelper.database;
    final String passwordHash = _hashPassword(password);
    final String now = _now();

    // 1. Insert user with 'new_user' role (id=4)
    final int userId = await db.insert('users', {
      'username': username,
      'email': email,
      'password_hash': passwordHash,
      'contact_number': contactNumber,
      'role_id': 4, // new_user
      'is_verified': 0,
      'is_active': 1,
      'login_count': 0,
      'created_at': now,
    });

    // 2. Audit log
    await db.insert('audit_logs', {
      'user_id': userId,
      'action': 'REGISTER',
      'details': 'User registered with new_user role.',
      'performed_at': now,
    });

    return userId;
  }

  // ─────────────── Login ───────────────

  /// Authenticate a user by email + password.
  ///
  /// On success: increments login_count, updates last_login_at,
  /// creates a session token, logs the event, and returns a fully
  /// enriched [UserModel] (with roleName, permissions, sessionToken).
  ///
  /// Returns `null` on invalid credentials or deactivated account.
  Future<UserModel?> loginUser(String email, String password) async {
    final db = await _dbHelper.database;
    final String passwordHash = _hashPassword(password);

    // 1. Verify credentials
    final List<Map<String, dynamic>> results = await db.query(
      'users',
      where: 'email = ? AND password_hash = ? AND is_active = 1',
      whereArgs: [email, passwordHash],
    );

    if (results.isEmpty) {
      // Optionally log failed attempt
      await db.insert('audit_logs', {
        'user_id': null,
        'action': 'LOGIN_FAILED',
        'details': 'Failed login attempt for email: $email',
        'performed_at': _now(),
      });
      return null;
    }

    final UserModel user = UserModel.fromMap(results.first);
    final String now = _now();

    // 2. Increment login_count and set last_login_at
    final int newLoginCount = user.loginCount + 1;
    await db.update(
      'users',
      {
        'login_count': newLoginCount,
        'last_login_at': now,
        'updated_at': now,
      },
      where: 'id = ?',
      whereArgs: [user.id],
    );

    // 3. Create session token
    final String sessionToken = _uuid.v4();
    // Session expiry: 1 hour for new/unverified users, 24 hours for existing users.
    final int expiryHours = (user.isVerified == 1 && newLoginCount > 1) ? 24 : 1;
    final String expiresAt =
        DateTime.now().toUtc().add(Duration(hours: expiryHours)).toIso8601String();

    // Deactivate any existing active sessions for this user
    await db.update(
      'user_sessions',
      {'is_active': 0},
      where: 'user_id = ? AND is_active = 1',
      whereArgs: [user.id],
    );

    await db.insert('user_sessions', {
      'user_id': user.id,
      'session_token': sessionToken,
      'created_at': now,
      'expires_at': expiresAt,
      'is_active': 1,
    });

    // 4. Audit log
    await db.insert('audit_logs', {
      'user_id': user.id,
      'action': 'LOGIN',
      'details': 'Successful login. Session expires: $expiresAt',
      'performed_at': now,
    });

    // 5. Return enriched user model
    final UserModel? enriched = await getUserWithRole(user.id!);
    if (enriched == null) return null;

    final List<String> perms = await getAllPermissionsForUser(user.id!);
    return enriched.copyWith(
      sessionToken: sessionToken,
      permissions: perms,
      loginCount: newLoginCount,
    );
  }

  // ─────────────── Logout ───────────────

  /// Deactivate a session by token and log the event.
  Future<bool> logoutUser(String sessionToken) async {
    final db = await _dbHelper.database;
    final String now = _now();

    // Find the session to get the user_id for audit log
    final List<Map<String, dynamic>> sessions = await db.query(
      'user_sessions',
      where: 'session_token = ? AND is_active = 1',
      whereArgs: [sessionToken],
    );

    if (sessions.isEmpty) return false;

    final int userId = sessions.first['user_id'] as int;

    // Deactivate session
    await db.update(
      'user_sessions',
      {'is_active': 0},
      where: 'session_token = ?',
      whereArgs: [sessionToken],
    );

    // Audit log
    await db.insert('audit_logs', {
      'user_id': userId,
      'action': 'LOGOUT',
      'details': 'Session deactivated.',
      'performed_at': now,
    });

    return true;
  }

  // ─────────────── Verification & Role Upgrade ───────────────

  /// Verify a user's account and automatically upgrade their role
  /// from 'new_user' (id=4) to 'existing_user' (id=3).
  /// Logs 'ROLE_UPGRADED' to audit_logs.
  Future<bool> verifyAndUpgradeUser(int userId) async {
    final db = await _dbHelper.database;
    final String now = _now();

    // 1. Set is_verified=1, change role to existing_user (id=3)
    final int count = await db.update(
      'users',
      {
        'is_verified': 1,
        'role_id': 3, // existing_user
        'updated_at': now,
      },
      where: 'id = ? AND is_verified = 0',
      whereArgs: [userId],
    );

    if (count > 0) {
      // 2. Audit log
      await db.insert('audit_logs', {
        'user_id': userId,
        'action': 'ROLE_UPGRADED',
        'details':
            'User verified and upgraded from new_user to existing_user.',
        'performed_at': now,
      });
      return true;
    }
    return false;
  }

  // ─────────────── User Queries ───────────────

  /// Fetch a user by ID with their role name (JOIN query).
  Future<UserModel?> getUserWithRole(int userId) async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.rawQuery('''
      SELECT u.*, r.role_name
      FROM users u
      JOIN roles r ON u.role_id = r.id
      WHERE u.id = ?
    ''', [userId]);

    if (results.isNotEmpty) {
      return UserModel.fromMap(results.first);
    }
    return null;
  }

  /// Fetch the user associated with an active, non-expired session token.
  /// Returns null if the token is invalid, expired, or deactivated.
  Future<UserModel?> getUserBySessionToken(String sessionToken) async {
    final db = await _dbHelper.database;

    final List<Map<String, dynamic>> sessions = await db.rawQuery('''
      SELECT s.user_id, s.expires_at
      FROM user_sessions s
      WHERE s.session_token = ? AND s.is_active = 1
    ''', [sessionToken]);

    if (sessions.isEmpty) return null;

    final String expiresAtStr = sessions.first['expires_at'] as String;
    final DateTime expiresAt = DateTime.parse(expiresAtStr);

    if (expiresAt.isBefore(DateTime.now().toUtc())) {
      // Expired — deactivate
      await db.update(
        'user_sessions',
        {'is_active': 0},
        where: 'session_token = ?',
        whereArgs: [sessionToken],
      );
      return null;
    }

    final int userId = sessions.first['user_id'] as int;
    final UserModel? user = await getUserWithRole(userId);
    if (user == null) return null;

    final List<String> perms = await getAllPermissionsForUser(userId);
    return user.copyWith(
      sessionToken: sessionToken,
      permissions: perms,
    );
  }

  // ─────────────── Permissions ───────────────

  /// Check whether a user has a specific permission by name.
  /// Uses a 3-table JOIN: users → role_permissions → permissions.
  Future<bool> checkPermission(int userId, String permissionName) async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.rawQuery('''
      SELECT COUNT(*) as count
      FROM users u
      JOIN role_permissions rp ON u.role_id = rp.role_id
      JOIN permissions p ON rp.permission_id = p.id
      WHERE u.id = ? AND p.permission_name = ?
    ''', [userId, permissionName]);

    return (results.first['count'] as int) > 0;
  }

  /// Return all permission names for a given user.
  Future<List<String>> getAllPermissionsForUser(int userId) async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.rawQuery('''
      SELECT p.permission_name
      FROM users u
      JOIN role_permissions rp ON u.role_id = rp.role_id
      JOIN permissions p ON rp.permission_id = p.id
      WHERE u.id = ?
    ''', [userId]);

    return results.map((r) => r['permission_name'] as String).toList();
  }

  /// Fetch a role with its full permission list.
  Future<RoleModel?> getRoleWithPermissions(int roleId) async {
    final db = await _dbHelper.database;

    // Get role
    final List<Map<String, dynamic>> roleRows = await db.query(
      'roles',
      where: 'id = ?',
      whereArgs: [roleId],
    );
    if (roleRows.isEmpty) return null;

    // Get permissions
    final List<Map<String, dynamic>> permRows = await db.rawQuery('''
      SELECT p.permission_name
      FROM role_permissions rp
      JOIN permissions p ON rp.permission_id = p.id
      WHERE rp.role_id = ?
    ''', [roleId]);

    final List<String> perms =
        permRows.map((r) => r['permission_name'] as String).toList();

    return RoleModel.fromMap(roleRows.first, permissions: perms);
  }

  // ─────────────── Admin Operations ───────────────

  /// Change a target user's role. Only callable by an admin.
  /// Validates that [adminUserId] actually has the 'admin' role.
  /// Logs 'ROLE_CHANGED' to audit_logs.
  Future<bool> changeUserRole(
      int adminUserId, int targetUserId, int newRoleId) async {
    final db = await _dbHelper.database;
    final String now = _now();

    // Verify the caller is an admin
    final UserModel? admin = await getUserWithRole(adminUserId);
    if (admin == null || admin.roleName != 'admin') {
      await db.insert('audit_logs', {
        'user_id': adminUserId,
        'action': 'PERMISSION_DENIED',
        'details':
            'Non-admin user attempted to change role of user $targetUserId.',
        'performed_at': now,
      });
      return false;
    }

    // Get old role for audit log detail
    final UserModel? target = await getUserWithRole(targetUserId);
    if (target == null) return false;

    final int count = await db.update(
      'users',
      {
        'role_id': newRoleId,
        'updated_at': now,
      },
      where: 'id = ?',
      whereArgs: [targetUserId],
    );

    if (count > 0) {
      await db.insert('audit_logs', {
        'user_id': adminUserId,
        'action': 'ROLE_CHANGED',
        'details':
            'Admin changed user $targetUserId role from ${target.roleName} (${target.roleId}) '
            'to role_id=$newRoleId.',
        'performed_at': now,
      });
      return true;
    }
    return false;
  }

  // ─────────────── Session Validation ───────────────

  /// Check whether a session token is active and not expired.
  /// Auto-deactivates expired sessions.
  Future<bool> isSessionValid(String sessionToken) async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.query(
      'user_sessions',
      where: 'session_token = ? AND is_active = 1',
      whereArgs: [sessionToken],
    );

    if (results.isEmpty) return false;

    final String expiresAtStr = results.first['expires_at'] as String;
    final DateTime expiresAt = DateTime.parse(expiresAtStr);

    if (expiresAt.isBefore(DateTime.now().toUtc())) {
      // Expired — deactivate
      await db.update(
        'user_sessions',
        {'is_active': 0},
        where: 'session_token = ?',
        whereArgs: [sessionToken],
      );
      return false;
    }

    return true;
  }

  // ─────────────── Validation Helpers ───────────────

  /// Check if an email address is already registered.
  Future<bool> isEmailTaken(String email) async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.query(
      'users',
      columns: ['id'],
      where: 'email = ?',
      whereArgs: [email],
      limit: 1,
    );
    return results.isNotEmpty;
  }

  /// Check if a username is already taken.
  Future<bool> isUsernameTaken(String username) async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.query(
      'users',
      columns: ['id'],
      where: 'username = ?',
      whereArgs: [username],
      limit: 1,
    );
    return results.isNotEmpty;
  }

  // ─────────────── Audit Logs ───────────────

  /// Fetch recent audit logs, optionally filtered by user ID.
  /// Returns at most [limit] rows ordered by most recent first.
  Future<List<Map<String, dynamic>>> getAuditLogs({
    int? userId,
    int limit = 50,
  }) async {
    final db = await _dbHelper.database;

    if (userId != null) {
      return await db.rawQuery('''
        SELECT al.*, u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE al.user_id = ?
        ORDER BY al.performed_at DESC
        LIMIT ?
      ''', [userId, limit]);
    }

    return await db.rawQuery('''
      SELECT al.*, u.username
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ORDER BY al.performed_at DESC
      LIMIT ?
    ''', [limit]);
  }

  /// Fetch all users (admin view).
  Future<List<UserModel>> getAllUsers() async {
    final db = await _dbHelper.database;
    final List<Map<String, dynamic>> results = await db.rawQuery('''
      SELECT u.*, r.role_name
      FROM users u
      JOIN roles r ON u.role_id = r.id
      ORDER BY u.created_at DESC
    ''');
    return results.map((r) => UserModel.fromMap(r)).toList();
  }
}
