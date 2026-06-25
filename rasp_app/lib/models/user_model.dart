// ==================== user_model.dart ====================
// Immutable data class representing a user row from the `users` table.
// Includes computed getters for RBAC status (isNewUser / isExistingUser)
// and optional fields populated via JOIN queries (roleName, permissions,
// sessionToken).

class UserModel {
  final int? id;
  final String username;
  final String email;
  final String passwordHash;
  final String contactNumber;
  final int roleId;
  final int isVerified; // 0 = unverified, 1 = verified
  final int isActive; // 0 = deactivated, 1 = active
  final int loginCount;
  final String? lastLoginAt;
  final String createdAt;
  final String? updatedAt;

  // ── Populated via JOIN / post-query enrichment ──
  /// Role name from the `roles` table (e.g. 'admin', 'new_user').
  final String? roleName;

  /// Permission names resolved from roles → role_permissions → permissions.
  final List<String> permissions;

  /// Active session token assigned after a successful login.
  final String? sessionToken;

  const UserModel({
    this.id,
    required this.username,
    required this.email,
    required this.passwordHash,
    required this.contactNumber,
    required this.roleId,
    this.isVerified = 0,
    this.isActive = 1,
    this.loginCount = 0,
    this.lastLoginAt,
    required this.createdAt,
    this.updatedAt,
    this.roleName,
    this.permissions = const [],
    this.sessionToken,
  });

  // ── RBAC Status Getters ──

  /// A NEW user has never logged in or is unverified.
  bool get isNewUser => loginCount == 0 || isVerified == 0;

  /// An EXISTING user has logged in at least once AND is verified.
  bool get isExistingUser => loginCount > 0 && isVerified == 1;

  /// Convenience: true if this user has the admin role.
  bool get isAdmin => roleName == 'admin';

  /// Convenience: true if this user has the moderator role.
  bool get isModerator => roleName == 'moderator';

  // ── Serialisation ──

  /// Construct a [UserModel] from a database row map.
  /// Handles nullable and optional columns gracefully.
  factory UserModel.fromMap(Map<String, dynamic> map) {
    return UserModel(
      id: map['id'] as int?,
      username: map['username'] as String,
      email: map['email'] as String,
      passwordHash: map['password_hash'] as String,
      contactNumber: map['contact_number'] as String,
      roleId: map['role_id'] as int,
      isVerified: map['is_verified'] as int? ?? 0,
      isActive: map['is_active'] as int? ?? 1,
      loginCount: map['login_count'] as int? ?? 0,
      lastLoginAt: map['last_login_at'] as String?,
      createdAt:
          map['created_at'] as String? ?? DateTime.now().toIso8601String(),
      updatedAt: map['updated_at'] as String?,
      roleName: map['role_name'] as String?,
      // permissions and sessionToken are NOT in the DB row;
      // they are injected by the repository layer.
    );
  }

  /// Convert to a map suitable for `db.insert()` / `db.update()`.
  /// Excludes computed/transient fields (roleName, permissions, sessionToken).
  Map<String, dynamic> toMap() {
    return {
      if (id != null) 'id': id,
      'username': username,
      'email': email,
      'password_hash': passwordHash,
      'contact_number': contactNumber,
      'role_id': roleId,
      'is_verified': isVerified,
      'is_active': isActive,
      'login_count': loginCount,
      'last_login_at': lastLoginAt,
      'created_at': createdAt,
      'updated_at': updatedAt,
    };
  }

  // ── Copy Helper ──

  UserModel copyWith({
    int? id,
    String? username,
    String? email,
    String? passwordHash,
    String? contactNumber,
    int? roleId,
    int? isVerified,
    int? isActive,
    int? loginCount,
    String? lastLoginAt,
    String? createdAt,
    String? updatedAt,
    String? roleName,
    List<String>? permissions,
    String? sessionToken,
  }) {
    return UserModel(
      id: id ?? this.id,
      username: username ?? this.username,
      email: email ?? this.email,
      passwordHash: passwordHash ?? this.passwordHash,
      contactNumber: contactNumber ?? this.contactNumber,
      roleId: roleId ?? this.roleId,
      isVerified: isVerified ?? this.isVerified,
      isActive: isActive ?? this.isActive,
      loginCount: loginCount ?? this.loginCount,
      lastLoginAt: lastLoginAt ?? this.lastLoginAt,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      roleName: roleName ?? this.roleName,
      permissions: permissions ?? this.permissions,
      sessionToken: sessionToken ?? this.sessionToken,
    );
  }

  @override
  String toString() {
    return 'UserModel(id: $id, username: $username, role: $roleName, '
        'verified: $isVerified, loginCount: $loginCount)';
  }
}
