// ==================== role_model.dart ====================

class RoleModel {
  final int id;
  final String roleName;
  final String? description;
  final List<String> permissions;

  const RoleModel({
    required this.id,
    required this.roleName,
    this.description,
    this.permissions = const [],
  });

  /// Convert a Database map to a RoleModel object
  factory RoleModel.fromMap(Map<String, dynamic> map, {List<String> permissions = const []}) {
    return RoleModel(
      id: map['id'] as int,
      roleName: map['role_name'] as String,
      description: map['description'] as String?,
      permissions: permissions,
    );
  }

  /// Convert a RoleModel object to a Database map
  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'role_name': roleName,
      'description': description,
    };
  }
}
