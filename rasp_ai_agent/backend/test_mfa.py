# backend/test_mfa.py
import httpx
import sys

BASE_URL = "http://127.0.0.1:8001"

def log(msg):
    print(f"\n>>> {msg}")

def main():
    client = httpx.Client()

    # Step 1: Initial Login (MFA is currently disabled)
    log("Logging in as superadmin...")
    res = client.post(f"{BASE_URL}/auth/login", json={
        "username": "superadmin",
        "password": "Demo@1234"
    })
    
    if res.status_code != 200:
        print(f"FAILED: Login failed: {res.status_code} - {res.text}")
        sys.exit(1)
        
    data = res.json()
    print("Login OK. Response status:", data.get("status", "NORMAL"))
    token = data["token"]

    # Step 2: Request MFA Enrollment
    log("Requesting MFA Enrollment...")
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post(f"{BASE_URL}/auth/mfa/enroll", headers=headers)
    if res.status_code != 200:
        print(f"FAILED: Enrollment failed: {res.status_code} - {res.text}")
        sys.exit(1)
        
    enroll_data = res.json()
    secret = enroll_data["secret"]
    otpauth_url = enroll_data["otpauth_url"]
    print(f"Enrollment OK. Secret: {secret}")
    print(f"OTPAuth URI: {otpauth_url}")

    # Generate 6-digit TOTP code using pyotp
    import pyotp
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    log(f"Generating current TOTP code: {current_code}")

    # Step 3: Confirm MFA Enrollment
    log("Confirming MFA Enrollment...")
    res = client.post(f"{BASE_URL}/auth/mfa/verify-enrollment", json={"code": current_code}, headers=headers)
    if res.status_code != 200:
        print(f"FAILED: Confirm enrollment failed: {res.status_code} - {res.text}")
        sys.exit(1)
        
    confirm_data = res.json()
    backup_codes = confirm_data["backup_codes"]
    print("MFA Enrolled successfully!")
    print(f"Generated backup recovery codes: {backup_codes}")

    # Step 4: Login again (now MFA is enabled)
    log("Logging in again with MFA active...")
    res = client.post(f"{BASE_URL}/auth/login", json={
        "username": "superadmin",
        "password": "Demo@1234"
    })
    if res.status_code != 200:
        print(f"FAILED: Login failed: {res.status_code} - {res.text}")
        sys.exit(1)
        
    mfa_req_data = res.json()
    status_field = mfa_req_data.get("status")
    print(f"Login Response: status={status_field}")
    if status_field != "MFA_REQUIRED":
        print("FAILED: Expected status to be MFA_REQUIRED")
        sys.exit(1)
        
    intermediate_token = mfa_req_data["intermediate_token"]
    print(f"Intermediate token received: {intermediate_token}")

    # Step 5: Try accessing /auth/me with intermediate token (should fail)
    log("Attempting to access /auth/me with unverified intermediate token...")
    res = client.get(f"{BASE_URL}/auth/me", headers={"Authorization": f"Bearer {intermediate_token}"})
    print(f"/auth/me response code: {res.status_code} (Expected: 401)")
    if res.status_code != 401:
        print("FAILED: Access should be denied with 401 before MFA is verified")
        sys.exit(1)
    print("Denied detail:", res.json().get("detail"))

    # Step 6: Complete Login via MFA verification
    mfa_code = totp.now()
    log(f"Submitting second-factor TOTP verification code: {mfa_code}")
    res = client.post(f"{BASE_URL}/auth/mfa/login", json={
        "intermediate_token": intermediate_token,
        "code": mfa_code
    })
    if res.status_code != 200:
        print(f"FAILED: MFA Login failed: {res.status_code} - {res.text}")
        sys.exit(1)
        
    mfa_login_data = res.json()
    final_token = mfa_login_data["token"]
    print("MFA Verification OK. Logged in successfully!")
    print("User role:", mfa_login_data["user"]["role"])

    # Step 7: Access /auth/me with final verified token (should succeed)
    log("Accessing /auth/me with verified token...")
    res = client.get(f"{BASE_URL}/auth/me", headers={"Authorization": f"Bearer {final_token}"})
    if res.status_code != 200:
        print(f"FAILED: /auth/me failed: {res.status_code} - {res.text}")
        sys.exit(1)
    print("/auth/me OK. Response user:", res.json()["username"])

    # Step 8: Reset MFA back for clean state during dev
    log("Resetting MFA for superadmin to default (disabled) state...")
    user_id = mfa_login_data["user"]["id"]
    res = client.post(f"{BASE_URL}/auth/mfa/reset", json={"user_id": user_id}, headers={"Authorization": f"Bearer {final_token}"})
    if res.status_code != 200:
        print(f"FAILED: MFA reset failed: {res.status_code} - {res.text}")
        sys.exit(1)
    print("MFA Reset OK:", res.json().get("message"))

    print("\n" + "="*40)
    print("MFA & SECOND-FACTOR VERIFICATION PASSED")
    print("="*40)

if __name__ == "__main__":
    main()
