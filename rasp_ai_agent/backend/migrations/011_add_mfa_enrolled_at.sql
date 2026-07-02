-- Add timestamp recorded when a dashboard user completes MFA enrollment.

ALTER TABLE dashboard_users ADD COLUMN mfa_enrolled_at TEXT;
