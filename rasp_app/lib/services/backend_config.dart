class BackendConfig {
  static const String securityApiBaseUrl = String.fromEnvironment(
    'RASP_BACKEND_URL',
    defaultValue: 'http://127.0.0.1:8001/api/v1',
  );
}
