from __future__ import annotations

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient

from app.api.auth_router import set_auth_db
from app.database.connection import DatabaseManager
from app.main import create_app


@pytest.mark.asyncio
async def test_mfa_enrollment_and_login_flow(test_db: DatabaseManager) -> None:
    set_auth_db(test_db)
    app = create_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post(
            "/auth/login",
            json={"username": "superadmin", "password": "Admin@Shield2024"},
        )
        assert login_response.status_code == 200
        token = login_response.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        enroll_response = await client.post("/auth/mfa/enroll", headers=headers)
        assert enroll_response.status_code == 200
        secret = enroll_response.json()["secret"]
        assert enroll_response.json()["otpauth_url"].startswith("otpauth://totp/")

        verify_response = await client.post(
            "/auth/mfa/verify-enrollment",
            headers=headers,
            json={"code": pyotp.TOTP(secret).now()},
        )
        assert verify_response.status_code == 200
        assert len(verify_response.json()["backup_codes"]) == 8

        mfa_login_response = await client.post(
            "/auth/login",
            json={"username": "superadmin", "password": "Admin@Shield2024"},
        )
        assert mfa_login_response.status_code == 200
        mfa_payload = mfa_login_response.json()
        assert mfa_payload["status"] == "MFA_REQUIRED"
        intermediate_token = mfa_payload["intermediate_token"]

        denied_response = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {intermediate_token}"},
        )
        assert denied_response.status_code == 401
        assert denied_response.json()["detail"] == "MFA verification required"

        complete_response = await client.post(
            "/auth/mfa/login",
            json={
                "intermediate_token": intermediate_token,
                "code": pyotp.TOTP(secret).now(),
            },
        )
        assert complete_response.status_code == 200
        final_token = complete_response.json()["token"]

        me_response = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {final_token}"},
        )
        assert me_response.status_code == 200
        assert me_response.json()["username"] == "superadmin"
