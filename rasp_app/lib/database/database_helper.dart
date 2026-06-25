// ==================== database_helper.dart ====================
// Singleton SQLite database manager for the RBAC security system.
// Creates all 6 tables, seeds default roles/permissions/admin user,
// and enforces foreign key constraints via PRAGMA.
//
// Schema version history:
//   v1 — Initial schema (6 tables, indexes, seed data)
//   v2 — Added moderator role-permission mappings

import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';

class DatabaseHelper {
  // --------------- Singleton Pattern ---------------
  static final DatabaseHelper _instance = DatabaseHelper._internal();
  static Database? _database;

  factory DatabaseHelper() => _instance;

  DatabaseHelper._internal();

  /// Current schema version — bump this when adding migrations.
  static const int _dbVersion = 2;

  /// Database name on disk.
  static const String _dbName = 'rbac_security.db';

  /// Lazy-initialised database accessor.
  Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDatabase();
    return _database!;
  }

  // --------------- Initialisation ---------------

  Future<Database> _initDatabase() async {
    final String path = join(await getDatabasesPath(), _dbName);
    return await openDatabase(
      path,
      version: _dbVersion,
      onCreate: _onCreate,
      onUpgrade: _onUpgrade,
      onDowngrade: onDatabaseDowngradeDelete,
      onConfigure: _onConfigure,
    );
  }

  /// Enable foreign key enforcement on every connection.
  Future<void> _onConfigure(Database db) async {
    await db.execute('PRAGMA foreign_keys = ON');
  }

  // --------------- Schema Creation (v1) ---------------

  Future<void> _onCreate(Database db, int version) async {
    // ── 1. Roles Table ──
    await db.execute('''
      CREATE TABLE roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      )
    ''');

    // ── 2. Permissions Table ──
    await db.execute('''
      CREATE TABLE permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        permission_name TEXT NOT NULL UNIQUE,
        description TEXT
      )
    ''');

    // ── 3. Role–Permission Junction Table ──
    await db.execute('''
      CREATE TABLE role_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_id INTEGER NOT NULL,
        permission_id INTEGER NOT NULL,
        UNIQUE(role_id, permission_id),
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
        FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
      )
    ''');

    // ── 4. Users Table ──
    await db.execute('''
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        role_id INTEGER NOT NULL,
        is_verified INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        login_count INTEGER DEFAULT 0,
        last_login_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT,
        FOREIGN KEY (role_id) REFERENCES roles (id)
      )
    ''');

    // ── 5. User Sessions Table ──
    await db.execute('''
      CREATE TABLE user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    ''');

    // ── 6. Audit Logs Table ──
    await db.execute('''
      CREATE TABLE audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        performed_at TEXT DEFAULT CURRENT_TIMESTAMP,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    ''');

    // ── Indexes for frequently queried columns ──
    await db.execute('CREATE INDEX idx_users_email ON users(email)');
    await db.execute('CREATE INDEX idx_users_username ON users(username)');
    await db.execute(
        'CREATE INDEX idx_sessions_token ON user_sessions(session_token)');

    // ── Seed default data ──
    await _seedDatabase(db);
  }

  // --------------- Schema Migrations ---------------

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    // Migrations run sequentially from oldVersion → newVersion.
    if (oldVersion < 2) {
      // v2: Seed moderator role-permission mappings (read, write, view_reports).
      // The moderator role (id=2) was created in v1 but had no permissions.
      await _seedModeratorPermissions(db);
    }
    // Future migrations go here:
    // if (oldVersion < 3) { ... }
  }

  // --------------- Seed Data ---------------

  Future<void> _seedDatabase(Database db) async {
    final String now = DateTime.now().toUtc().toIso8601String();

    // ── 1. Roles ──
    // Insertion order determines IDs: admin=1, moderator=2, existing_user=3, new_user=4
    final List<Map<String, dynamic>> roles = [
      {
        'role_name': 'admin',
        'description': 'Full system access',
        'created_at': now,
      },
      {
        'role_name': 'moderator',
        'description': 'Limited management access',
        'created_at': now,
      },
      {
        'role_name': 'existing_user',
        'description': 'Verified standard user',
        'created_at': now,
      },
      {
        'role_name': 'new_user',
        'description': 'Unverified initial user',
        'created_at': now,
      },
    ];
    for (var role in roles) {
      await db.insert('roles', role);
    }

    // ── 2. Permissions ──
    // Insertion order determines IDs: read=1, write=2, delete=3, manage_users=4, view_reports=5
    final List<Map<String, dynamic>> permissions = [
      {'permission_name': 'read', 'description': 'Can view data'},
      {'permission_name': 'write', 'description': 'Can create/update data'},
      {'permission_name': 'delete', 'description': 'Can remove data'},
      {
        'permission_name': 'manage_users',
        'description': 'Can edit roles/users',
      },
      {
        'permission_name': 'view_reports',
        'description': 'Can view analytics',
      },
    ];
    for (var permission in permissions) {
      await db.insert('permissions', permission);
    }

    // ── 3. Role → Permission Mappings ──

    // Admin (id=1) → ALL permissions (1–5)
    for (int i = 1; i <= 5; i++) {
      await db
          .insert('role_permissions', {'role_id': 1, 'permission_id': i});
    }

    // Moderator (id=2) → read, write, view_reports
    await db
        .insert('role_permissions', {'role_id': 2, 'permission_id': 1});
    await db
        .insert('role_permissions', {'role_id': 2, 'permission_id': 2});
    await db
        .insert('role_permissions', {'role_id': 2, 'permission_id': 5});

    // Existing User (id=3) → read, write
    await db
        .insert('role_permissions', {'role_id': 3, 'permission_id': 1});
    await db
        .insert('role_permissions', {'role_id': 3, 'permission_id': 2});

    // New User (id=4) → read only
    await db
        .insert('role_permissions', {'role_id': 4, 'permission_id': 1});

    // ── 4. Default Admin User ──
    final String adminPasswordHash =
        sha256.convert(utf8.encode('Admin@123')).toString();
    await db.insert('users', {
      'username': 'admin',
      'email': 'admin@app.com',
      'password_hash': adminPasswordHash,
      'contact_number': '+1234567890',
      'role_id': 1, // Admin role
      'is_verified': 1,
      'is_active': 1,
      'login_count': 0,
      'created_at': now,
    });

    // ── 5. Audit log for system initialisation ──
    await db.insert('audit_logs', {
      'user_id': 1,
      'action': 'SYSTEM_INIT',
      'details': 'Default roles, permissions, and admin user created.',
      'performed_at': now,
    });
  }

  /// Seed moderator permissions — used both in onCreate and onUpgrade(v2).
  Future<void> _seedModeratorPermissions(Database db) async {
    // Moderator (role_id=2) gets: read(1), write(2), view_reports(5)
    // Using INSERT OR IGNORE to avoid duplicates on fresh installs.
    await db.execute(
      'INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [2, 1],
    );
    await db.execute(
      'INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [2, 2],
    );
    await db.execute(
      'INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [2, 5],
    );
  }
}
