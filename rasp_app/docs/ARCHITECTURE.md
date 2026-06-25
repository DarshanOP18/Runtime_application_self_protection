# Architecture

## Overview

The application is split into five layers:

1. Launch and device security gate
2. Authentication and session layer
3. Role-based application shell
4. RASP security center
5. AI assistant and reporting services

## Component Map

```mermaid
flowchart TD
  A[main.dart] --> B[RaspGate]
  B --> C[RaspService]
  C --> D[Native MethodChannels]
  C --> E[DeviceFingerprintService]
  C --> F[SslPinningService]
  C --> G[GeoFilterService]
  C --> H[ThreatReporterService]
  B --> I[AuthGate]
  I --> J[LoginScreen]
  J --> K[UserRepository]
  K --> L[DatabaseHelper / SQLite]
  I --> M[DashboardScreen]
  M --> N[HomeScreen]
  M --> O[AgentChatWidget]
  M --> P[Audit Log / Admin Panels]
```

## Runtime Flow

```mermaid
sequenceDiagram
  participant User
  participant App
  participant Gate as RaspGate
  participant Auth as AuthGate
  participant Sec as RaspService
  participant DB as SQLite
  participant AI as Agent Assistant

  User->>App: Open app
  App->>Gate: start checks
  Gate->>Sec: runChecks()
  Sec->>DB: read sessions/roles
  Sec-->>Gate: RaspCheckResult
  Gate->>Auth: continue if safe
  Auth->>DB: validate session token
  Auth-->>App: Login or Dashboard
  User->>AI: tap bot
  AI-->>User: simple greeting / helper response
```

## Data Storage

The app stores:

- users
- roles
- permissions
- role_permissions
- user_sessions
- audit_logs

The schema is defined in `lib/database/database_helper.dart`.

## Security Design Notes

- Security checks are intentionally layered.
- The result model exposes both raw flags and consolidated threat summaries.
- Blocking and deception are driven from the same result object.
- Screenshot protection is enabled early during runtime checks.
- Threat telemetry is isolated so reporting failures do not crash the app.
