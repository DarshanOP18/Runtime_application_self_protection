# FILE: backend/seed_demo_data.py
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
import sqlite3
import datetime
from datetime import timedelta
import random
import hashlib
import json
import os
import sys

# ──────────────────────────────────────────────────────────────────────
# SECTION 5 — FALLBACK BCRYPT HASH
# ──────────────────────────────────────────────────────────────────────
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"])
    DEMO_PASSWORD_HASH = pwd_context.hash("Demo@1234")
    print("[auth] Using fresh bcrypt hash")
except ImportError:
    DEMO_PASSWORD_HASH = (
        "$2b$12$EixZaYVK1fsbw1ZfbX3OX"
        "ePaWxn96p36WQoeG6Lruj3vjPGga31lW"
    )
    print("[auth] passlib not found — using fallback hash")
    print("[auth] Install with: pip install passlib[bcrypt]")

# DB Path configuration
DB_PATH = "./data/rbac_security.db"

def main():
    # Parse --force argument
    force_mode = "--force" in sys.argv

    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database file not found at {DB_PATH}.")
        print("Please run this script from the 'rasp_ai_agent/backend' directory.")
        sys.exit(1)

    # Establish connection
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if migration tables exist (verify DB has been initialized)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dashboard_users'")
    if not cursor.fetchone():
        print("ERROR: Run migrations first (python app.py once) then run this seeder.")
        conn.close()
        sys.exit(1)

    # If force mode, clear existing tables
    if force_mode:
        print("Force mode: clearing existing data...")
        tables_to_clear = [
            "threat_history", "device_security_profile", "security_chat_history",
            "risk_assessments", "dashboard_users", "dashboard_sessions",
            "dashboard_audit_logs", "incidents", "fraud_cases",
            "compliance_reports", "notifications", "api_keys"
        ]
        for tbl in tables_to_clear:
            try:
                cursor.execute(f"DELETE FROM {tbl}")
            except sqlite3.OperationalError as e:
                print(f"Could not clear table {tbl}: {e}")
        conn.commit()
    else:
        # Check if already seeded to prevent duplicate work unless force is used
        check_tables = ["threat_history", "incidents", "fraud_cases"]
        already_has_data = False
        for tbl in check_tables:
            cursor.execute(f"SELECT COUNT(*) FROM {tbl}")
            if cursor.fetchone()[0] > 5:
                already_has_data = True
                break
        if already_has_data:
            print("Skipping — already has data (use --force to reset)")
            conn.close()
            sys.exit(0)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART A — DASHBOARD USERS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[1/11] Seeding dashboard users...")
    users = [
        ("superadmin", "Rajesh Kumar", "rajesh.kumar@shield.local", "SUPER_ADMIN", "Shield Security HQ"),
        ("sec.admin", "Priya Sharma", "priya.sharma@hdfc.shield.local", "SECURITY_ADMIN", "HDFC Bank Security"),
        ("soc.manager", "Amit Patel", "amit.patel@hdfc.shield.local", "SOC_MANAGER", "HDFC Bank Security"),
        ("soc.analyst", "Neha Singh", "neha.singh@hdfc.shield.local", "SOC_ANALYST", "HDFC Bank Security"),
        ("fraud.manager", "Suresh Reddy", "suresh.reddy@hdfc.shield.local", "FRAUD_MANAGER", "HDFC Bank Fraud Team"),
        ("fraud.analyst", "Kavya Nair", "kavya.nair@hdfc.shield.local", "FRAUD_ANALYST", "HDFC Bank Fraud Team"),
        ("compliance.mgr", "Vikram Joshi", "vikram.joshi@hdfc.shield.local", "COMPLIANCE_MANAGER", "HDFC Bank Compliance"),
        ("compliance.off", "Meera Iyer", "meera.iyer@hdfc.shield.local", "COMPLIANCE_OFFICER", "HDFC Bank Compliance"),
        ("auditor", "Deepak Verma", "deepak.verma@audit.shield.local", "READ_ONLY_AUDITOR", "External Audit Firm")
    ]

    for username, full_name, email, role, org in users:
        cursor.execute("""
            INSERT OR IGNORE INTO dashboard_users (username, full_name, email, password_hash, role, organization)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, full_name, email, DEMO_PASSWORD_HASH, role, org))
    conn.commit()

    # Query mapping of roles to user IDs for reference later
    cursor.execute("SELECT id, username, role FROM dashboard_users")
    db_users = cursor.fetchall()
    user_id_map = {row[1]: row[0] for row in db_users}
    role_id_map = {row[2]: row[0] for row in db_users}

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART B — DEVICE PROFILES (25 devices)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[2/11] Seeding device profiles...")
    device_ids = [
        "ANDR-2024-A1B2C3", "ANDR-2024-D4E5F6", "ANDR-2024-G7H8I9", "ANDR-2024-J1K2L3",
        "ANDR-2024-M4N5O6", "ANDR-2024-P7Q8R9", "ANDR-2024-S1T2U3", "ANDR-2024-V4W5X6",
        "ANDR-2024-Y7Z8A9", "ANDR-2024-B1C2D3", "IOS-2024-E4F5G6",  "IOS-2024-H7I8J9",
        "IOS-2024-K1L2M3",  "IOS-2024-N4O5P6",  "IOS-2024-Q7R8S9",  "IOS-2024-T1U2V3",
        "IOS-2024-W4X5Y6",  "IOS-2024-Z7A8B9",  "IOS-2024-C1D2E3",  "IOS-2024-F4G5H6",
        "ANDR-2024-T1E2S3", "ANDR-2024-V1I2P3", "IOS-2024-B1N2K3",  "ANDR-2024-F1R2D3",
        "IOS-2024-S1E2C4"
    ]

    low_devices = device_ids[:8]
    med_devices = device_ids[8:16]
    high_devices = device_ids[16:21]
    crit_devices = device_ids[21:]

    # Pre-generate Specs
    device_specs = {}
    for d_id in device_ids:
        is_ios = d_id.startswith("IOS")
        if is_ios:
            model = random.choice(["iPhone 15 Pro Max", "iPhone 14", "iPhone 13 mini", "iPad Pro M2", "iPhone 15", "iPhone 12 Pro"])
            os_ver = random.choice(["17.2", "16.5", "17.0"])
        else:
            model = random.choice(["Samsung Galaxy S24", "OnePlus 13", "Xiaomi 14 Pro", "Realme GT 5", "Vivo X100", "Oppo Find X7", "Google Pixel 8 Pro", "Motorola Edge 50"])
            os_ver = random.choice(["14.0", "13.0", "12.0"])
        device_specs[d_id] = {"model": model, "os": os_ver, "app": "1.0.0"}

    # Seed profiles
    for d_id in device_ids:
        specs = device_specs[d_id]
        total_events = random.randint(5, 150)
        
        # Determine risk profile
        if d_id in crit_devices:
            risk = "CRITICAL"
            is_blocked = 1
            block_reason = "Persistent root access with active Frida instrumentation"
        elif d_id in high_devices:
            risk = "HIGH"
            is_blocked = 0
            block_reason = None
        elif d_id in med_devices:
            risk = "MEDIUM"
            is_blocked = 0
            block_reason = None
        else:
            risk = "LOW"
            is_blocked = 0
            block_reason = None

        first_seen = (datetime.datetime.now() - timedelta(days=random.randint(30, 90))).strftime("%Y-%m-%d %H:%M:%S")
        last_seen = (datetime.datetime.now() - timedelta(days=random.randint(0, 7), hours=random.randint(0, 23))).strftime("%Y-%m-%d %H:%M:%S")
        user_id = random.choice(list(user_id_map.values()))

        cursor.execute("""
            INSERT OR REPLACE INTO device_security_profile (
                device_id, user_id, device_model, os_version, app_version,
                first_seen_at, last_seen_at, total_threat_events, highest_risk_ever,
                is_blocked, block_reason, trusted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (d_id, user_id, specs["model"], specs["os"], specs["app"], first_seen, last_seen, total_events, risk, is_blocked, block_reason))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART C — THREAT HISTORY
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[3/11] Seeding threat history (200 records)...")
    
    # Combinations structure
    low_combos = [
        {"flags": ["vpn_detected"], "score": 15, "combo_name": "vpn_only", "summary": {"active_threats": ["vpn_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Virtual Private Network connection detected. Traffic is routed via an external tunnel.",
         "rec": "1. Disconnect VPN if not required. 2. Verify network configuration settings."},
        {"flags": ["screenshot_detected"], "score": 10, "combo_name": "screenshot_only", "summary": {"active_threats": ["screenshot_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "App captured a screenshot event. Sensitive transaction content might have been exposed.",
         "rec": "1. Avoid taking screenshots of transactional screens. 2. Restrict overlay app permissions."},
        {"flags": ["vpn_detected", "time_spoof"], "score": 45, "combo_name": "vpn_time", "summary": {"active_threats": ["vpn_detected", "time_spoof"], "combination": "none", "multiplier": 1.0},
         "exp": "VPN interface active alongside custom timezone or device clock deviation.",
         "rec": "1. Set device time settings to automatic. 2. Turn off VPN services."},
        {"flags": ["location_spoof"], "score": 35, "combo_name": "location_spoof", "summary": {"active_threats": ["location_spoof"], "combination": "none", "multiplier": 1.0},
         "exp": "GPS mock location services detected. Device location coordinates are simulated.",
         "rec": "1. Disable mock location providers in system developer settings."}
    ]

    med_combos = [
        {"flags": ["root_detected"], "score": 50, "combo_name": "root_only", "summary": {"active_threats": ["root_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Superuser binaries detected. Operating system sandbox security is compromised.",
         "rec": "1. Run the application on an unrooted device. 2. Reset device OS to factory official settings."},
        {"flags": ["emulator_detected", "debugger_detected"], "score": 70, "combo_name": "emulator_debugger", "summary": {"active_threats": ["emulator_detected", "debugger_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Virtual device environment identified with an attached active runtime debugger.",
         "rec": "1. Close debugging cables. 2. Ensure application runs on a physical, consumer-grade device."},
        {"flags": ["tamper_detected"], "score": 60, "combo_name": "tamper_only", "summary": {"active_threats": ["tamper_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Application integrity verification failed. Binary signature mismatch detected.",
         "rec": "1. Uninstall application immediately. 2. Re-download from the official app store."},
        {"flags": ["frida_detected", "vpn_detected"], "score": 95, "combo_name": "frida_vpn", "summary": {"active_threats": ["frida_detected", "vpn_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Runtime instrumentation framework (Frida) detected in combination with active VPN network routing.",
         "rec": "1. Terminate all background Frida server processes. 2. Disconnect VPN."}
    ]

    high_combos = [
        {"flags": ["root_detected", "debugger_detected"], "score": 90, "combo_name": "root_debugger", "summary": {"active_threats": ["root_detected", "debugger_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Attached debugger detected on a rooted operating system. Attacker can read active RAM variables.",
         "rec": "1. Stop USB debugging. 2. Unroot device and restart application."},
        {"flags": ["frida_detected", "hook_detected"], "score": 150, "combo_name": "frida_hook", "summary": {"active_threats": ["frida_detected", "hook_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Dynamic framework instrumentation alongside active API hook monitoring. Suggests runtime library hijack.",
         "rec": "1. Remove hooking modules (Xposed/LSPosed). 2. Shut down dynamic code injectors."},
        {"flags": ["tamper_detected", "overlay_detected", "accessibility_abuse"], "score": 110, "combo_name": "tamper_overlay_access", "summary": {"active_threats": ["tamper_detected", "overlay_detected", "accessibility_abuse"], "combination": "none", "multiplier": 1.0},
         "exp": "Credential harvesting vector: repackaged app combined with window overlay drawing and accessibility scraping.",
         "rec": "1. Review and disable suspect accessibility services. 2. Reinstall application from official source."},
        {"flags": ["root_detected", "vpn_detected", "proxy_detected"], "score": 85, "combo_name": "root_vpn_proxy", "summary": {"active_threats": ["root_detected", "vpn_detected", "proxy_detected"], "combination": "none", "multiplier": 1.0},
         "exp": "Root privileges combined with custom proxy configurations. Potential Man-in-the-Middle network intercept.",
         "rec": "1. Remove network proxy server configurations. 2. Disconnect VPN and reboot."}
    ]

    crit_combos = [
        {"flags": ["root_detected", "frida_detected"], "score": 169, "combo_name": "root_frida", "summary": {"active_threats": ["root_detected", "frida_detected"], "combination": "root_frida", "multiplier": 1.3},
         "exp": "Device is rooted and dynamic Frida injection is active. Severe reverse engineering risk.",
         "rec": "1. Block device session immediately. 2. Force complete OS wipe. 3. Re-enroll user manually."},
        {"flags": ["malware_detected", "root_detected"], "score": 195, "combo_name": "malware_root", "summary": {"active_threats": ["malware_detected", "root_detected"], "combination": "malware_root", "multiplier": 1.3},
         "exp": "Malware signature found running on a rooted device. Sandbox boundaries are ineffective.",
         "rec": "1. Quarantine system. 2. Run antivirus to isolate malicious APK. 3. Force re-key credentials."},
        {"flags": ["root_detected", "frida_detected", "tamper_detected"], "score": 285, "combo_name": "root_frida_tamper", "summary": {"active_threats": ["root_detected", "frida_detected", "tamper_detected"], "combination": "root_frida_tamper", "multiplier": 1.5},
         "exp": "App package tampered with, executing dynamic scripts via Frida on a rooted operating system.",
         "rec": "1. Lock corporate account permissions. 2. Revoke user security profile. 3. Wipe app data."},
        {"flags": ["frida_detected", "hook_detected", "debugger_detected"], "score": 247, "combo_name": "frida_hook_debugger", "summary": {"active_threats": ["frida_detected", "hook_detected", "debugger_detected"], "combination": "frida_hook_debugger", "multiplier": 1.3},
         "exp": "Full debugging suite active. Dynamic code hooks and active memory inspectors are bound to the process.",
         "rec": "1. Force quit application. 2. Invalidate OAuth session tokens. 3. Block active IP address."}
    ]

    threat_pool = []
    
    # helper to assign devices based on risk level
    def pick_device(risk_lvl):
        if risk_lvl == "CRITICAL":
            return random.choice(crit_devices) if random.random() < 0.7 else random.choice(high_devices)
        elif risk_lvl == "HIGH":
            return random.choice(high_devices) if random.random() < 0.6 else random.choice(crit_devices if random.random() < 0.5 else med_devices)
        elif risk_lvl == "MEDIUM":
            return random.choice(med_devices) if random.random() < 0.7 else random.choice(low_devices if random.random() < 0.5 else high_devices)
        else:
            return random.choice(low_devices) if random.random() < 0.8 else random.choice(med_devices)

    # Generate 80 LOW
    for _ in range(80):
        threat_pool.append(("LOW", random.choice(low_combos)))
    # Generate 60 MEDIUM
    for _ in range(60):
        threat_pool.append(("MEDIUM", random.choice(med_combos)))
    # Generate 40 HIGH
    for _ in range(40):
        threat_pool.append(("HIGH", random.choice(high_combos)))
    # Generate 20 CRITICAL
    for _ in range(20):
        threat_pool.append(("CRITICAL", random.choice(crit_combos)))

    THREAT_FLAGS_KEYS = [
        "root_detected", "frida_detected", "debugger_detected", "emulator_detected",
        "tamper_detected", "vpn_detected", "proxy_detected", "overlay_detected",
        "accessibility_abuse", "hook_detected", "location_spoof", "time_spoof",
        "malware_detected", "screenshot_detected"
    ]

    raw_threat_records = []

    for lvl, combo in threat_pool:
        dev_id = pick_device(lvl)
        specs = device_specs[dev_id]

        # Growth pattern: concentrate dates towards recent days
        day_offset = int((random.random() ** 1.8) * 30)
        dt = datetime.datetime.now() - timedelta(days=day_offset, hours=random.randint(0, 23), minutes=random.randint(0, 59))
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")

        uid = random.choice(list(user_id_map.values()))
        payload = {"device_id": dev_id, "user_id": uid, "device_model": specs["model"], "os_version": specs["os"], "app_version": specs["app"]}
        for f in THREAT_FLAGS_KEYS:
            payload[f] = 1 if f in combo["flags"] else 0

        raw_threat_records.append({
            "device_id": dev_id,
            "user_id": uid,
            "flags": combo["flags"],
            "score": combo["score"],
            "level": lvl,
            "summary": json.dumps(combo["summary"]),
            "exp": combo["exp"],
            "rec": combo["rec"],
            "raw_payload": json.dumps(payload),
            "created_at": dt_str
        })

    # Sort chronologically so ID matches temporal sequence
    raw_threat_records.sort(key=lambda x: x["created_at"])

    # Insert into DB and populate risk assessments
    print("[4/11] Seeding risk assessments...")
    for rec in raw_threat_records:
        cursor.execute(f"""
            INSERT INTO threat_history (
                device_id, user_id, 
                root_detected, frida_detected, debugger_detected, emulator_detected,
                tamper_detected, vpn_detected, proxy_detected, overlay_detected,
                accessibility_abuse, hook_detected, location_spoof, time_spoof,
                malware_detected, screenshot_detected,
                risk_score, risk_level, threat_summary, llm_explanation, llm_recommendation,
                raw_payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rec["device_id"], rec["user_id"],
            1 if "root_detected" in rec["flags"] else 0,
            1 if "frida_detected" in rec["flags"] else 0,
            1 if "debugger_detected" in rec["flags"] else 0,
            1 if "emulator_detected" in rec["flags"] else 0,
            1 if "tamper_detected" in rec["flags"] else 0,
            1 if "vpn_detected" in rec["flags"] else 0,
            1 if "proxy_detected" in rec["flags"] else 0,
            1 if "overlay_detected" in rec["flags"] else 0,
            1 if "accessibility_abuse" in rec["flags"] else 0,
            1 if "hook_detected" in rec["flags"] else 0,
            1 if "location_spoof" in rec["flags"] else 0,
            1 if "time_spoof" in rec["flags"] else 0,
            1 if "malware_detected" in rec["flags"] else 0,
            1 if "screenshot_detected" in rec["flags"] else 0,
            rec["score"], rec["level"], rec["summary"], rec["exp"], rec["rec"],
            rec["raw_payload"], rec["created_at"]
        ))
        threat_id = cursor.lastrowid
        
        # Breakdown JSON construction
        bk = {}
        for f in rec["flags"]:
            if f == "root_detected": bk[f] = 50
            elif f == "frida_detected": bk[f] = 80
            elif f == "debugger_detected": bk[f] = 40
            elif f == "emulator_detected": bk[f] = 30
            elif f == "tamper_detected": bk[f] = 60
            elif f == "vpn_detected": bk[f] = 15
            elif f == "proxy_detected": bk[f] = 20
            elif f == "overlay_detected": bk[f] = 25
            elif f == "accessibility_abuse": bk[f] = 25
            elif f == "hook_detected": bk[f] = 70
            elif f == "location_spoof": bk[f] = 35
            elif f == "time_spoof": bk[f] = 30
            elif f == "malware_detected": bk[f] = 90
            elif f == "screenshot_detected": bk[f] = 10

        summary_data = json.loads(rec["summary"])
        if summary_data.get("multiplier", 1.0) > 1.0:
            bk["combination_multiplier"] = summary_data["multiplier"]
        bk["final_score"] = rec["score"]

        cursor.execute("""
            INSERT INTO risk_assessments (device_id, threat_id, risk_score, risk_level, threat_flags, score_breakdown, assessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (rec["device_id"], threat_id, rec["score"], rec["level"], json.dumps(rec["flags"]), json.dumps(bk), rec["created_at"]))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART E — SECURITY CHAT HISTORY (30 sessions)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[5/11] Seeding security chat history...")
    qa_pairs = [
        ("What is Frida and why is it dangerous?",
         "Frida is a dynamic binary instrumentation framework widely used by security researchers and malicious actors alike. It allows runtime injection of JavaScript code into running processes, enabling attackers to bypass certificate pinning, extract encryption keys, modify application behavior, and exfiltrate sensitive data without modifying the APK."),
        ("My device shows CRITICAL risk. What should I do?",
         "A CRITICAL risk level indicates multiple severe threat signals have been detected simultaneously. Immediate actions required: 1) Revoke the active session immediately. 2) Notify the device user to stop using the banking application. 3) Initiate a device forensics investigation."),
        ("What is root detection and can it be bypassed?",
         "Root detection identifies if the Android operating system has been modified to grant unrestricted superuser privileges. Common bypass methods include Magisk Hide, which conceals root from specific apps, or dynamic hooking using Frida to spoof check returns."),
        ("Explain SSL certificate pinning",
         "SSL certificate pinning is a technique where the application validates the server certificate against a known, hardcoded value rather than trusting any certificate in the device's trust store. This prevents Man-in-the-Middle (MITM) intercepts."),
        ("What does the combination multiplier mean?",
         "The RASP threat scoring engine applies combination multipliers when multiple dangerous threat signals are detected simultaneously. For example, root detection alone scores 50 (MEDIUM risk), but root combined with Frida detection applies a 1.3x multiplier, resulting in 169 (CRITICAL) risk.")
    ]

    for i in range(1, 31):
        sess_id = f"sess_demo_{i:03d}"
        dev_id = random.choice(device_ids)
        u_id = random.choice(list(user_id_map.values()))
        
        # 2-6 messages (1-3 turns)
        num_turns = random.randint(1, 3)
        base_time = datetime.datetime.now() - timedelta(days=random.randint(1, 14), hours=random.randint(0, 23))
        
        for t in range(num_turns):
            q, a = qa_pairs[(i + t) % len(qa_pairs)]
            q_time = (base_time + timedelta(minutes=t*5)).strftime("%Y-%m-%d %H:%M:%S")
            a_time = (base_time + timedelta(minutes=t*5, seconds=random.randint(2, 5))).strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute("""
                INSERT INTO security_chat_history (session_id, device_id, user_id, role, message, token_count, created_at)
                VALUES (?, ?, ?, 'user', ?, ?, ?)
            """, (sess_id, dev_id, u_id, q, len(q.split()), q_time))
            
            cursor.execute("""
                INSERT INTO security_chat_history (session_id, device_id, user_id, role, message, token_count, created_at)
                VALUES (?, ?, ?, 'assistant', ?, ?, ?)
            """, (sess_id, dev_id, u_id, a, len(a.split()), a_time))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART F — INCIDENTS (25 incidents)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[6/11] Seeding incidents...")
    inc_titles = {
        "CRITICAL": [
            "Active Frida Attack on Customer Device — HDFC Mumbai",
            "Root + Malware Detected: Corporate Account Holder",
            "Coordinated Attack: 12 Devices Simultaneously Rooted",
            "Runtime Code Injection Attempt — Loan Processing",
            "Device Binding Bypass Attempt — High Value Account"
        ],
        "HIGH": [
            "App Tampering Detected — Suspected Repackaged APK",
            "Debugger Attached During Net Banking Session",
            "VPN + Proxy Combination: Possible MITM Attempt",
            "Emulator Farm Detected — Bulk Account Testing",
            "Accessibility Service Abuse — Screen Reading Active",
            "Multiple Failed Certificate Pinning Checks",
            "Location Spoofing During International Transfer",
            "Overlay Attack Attempt on Login Screen"
        ],
        "MEDIUM": [
            "VPN Usage Flagged During Large Transaction",
            "Developer Mode Active on Employee Device",
            "Screenshot Captured During Sensitive Screen",
            "Time Manipulation Detected — Possible Replay Attack",
            "USB Debugging Active — Violation of Policy",
            "Emulator Detected — Test Environment Suspected",
            "Geo-restriction Violation: Access from Flagged IP",
            "Repeated Session Token Usage After Expiry"
        ],
        "LOW": [
            "VPN Usage — User Notified of Policy",
            "Screenshot Detected — Low Risk Device",
            "Routine Security Check Failed — Device Outdated",
            "App Version Mismatch — Update Required"
        ]
    }

    inc_flat = []
    for sev, titles in inc_titles.items():
        for t in titles:
            inc_flat.append((sev, t))

    # incident statuses (total 25): 8 OPEN, 7 INVESTIGATING, 3 ESCALATED, 7 RESOLVED
    inc_statuses = (["OPEN"] * 8) + (["INVESTIGATING"] * 7) + (["ESCALATED"] * 3) + (["RESOLVED"] * 7)
    random.shuffle(inc_statuses)

    for i in range(25):
        inc_num = f"INC-202606{i+1:02d}-0001"
        sev, title = inc_flat[i]
        status = inc_statuses[i]
        dev_id = random.choice(device_ids)
        assigned_to = user_id_map["soc.analyst"] if random.random() < 0.7 else user_id_map["soc.manager"]
        created_by = user_id_map["soc.manager"]
        risk_score = 180 if sev == "CRITICAL" else 110 if sev == "HIGH" else 60 if sev == "MEDIUM" else 20
        
        created_dt = datetime.datetime.now() - timedelta(days=random.randint(1, 25), hours=random.randint(0, 23))
        created_str = created_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        if status == "RESOLVED":
            resolved_str = (created_dt + timedelta(hours=random.randint(2, 48))).strftime("%Y-%m-%d %H:%M:%S")
        else:
            resolved_str = None

        notes = [
            {
                "author": "Neha Singh",
                "timestamp": (created_dt + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S"),
                "note": f"Investigation started. Threat level is {sev}. Analyzing target device fingerprint {dev_id} for root and memory integrity checks."
            }
        ]
        if status == "RESOLVED":
            notes.append({
                "author": "Amit Patel",
                "timestamp": (created_dt + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S"),
                "note": "Threat isolated. Customer confirmed device factory reset. Safe signature verified on recent checks."
            })

        cursor.execute("""
            INSERT INTO incidents (
                incident_number, title, description, severity, status, device_id,
                assigned_to, created_by, threat_type, risk_score, notes, resolved_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            inc_num, title, f"RASP Alert triggered: {title}. Risk score {risk_score}.", sev, status, dev_id,
            assigned_to, created_by, sev.lower() + "_threat", risk_score, json.dumps(notes), resolved_str, created_str, created_str
        ))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART G — FRAUD CASES (15 fraud cases)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[7/11] Seeding fraud cases...")
    fraud_titles = [
        # SIM Swap
        ("SIM Swap", "CRITICAL", "SIM Swap Suspected — Customer Reports Unknown OTP",
         {"carrier": "Airtel", "sim_serial_changed": True, "time_difference_hours": 2}),
        ("SIM Swap", "HIGH", "Duplicate SIM Detected — Account Access from New Device",
         {"carrier": "Jio", "sim_serial_changed": True, "time_difference_hours": 6}),
        ("SIM Swap", "HIGH", "SIM Change + Device Change Within 24 Hours",
         {"carrier": "Vodafone", "sim_serial_changed": True, "time_difference_hours": 12}),
        # Device Clone
        ("Device Clone", "HIGH", "Cloned Device Detected — Parallel Space App Found",
         {"dual_app_environment": "Parallel Space", "is_cloned_app": True}),
        ("Device Clone", "MEDIUM", "Dual SIM + Device Clone Combination Risk",
         {"dual_app_environment": "DualSpace Pro", "is_cloned_app": True}),
        ("Device Clone", "HIGH", "Identical Device Fingerprint from Two Locations",
         {"fingerprint_collision": True, "remote_ip": "103.45.21.90"}),
        # Impossible Travel
        ("Impossible Travel", "CRITICAL", "Mumbai to London in 45 Minutes — Physical Impossible",
         {"location_1": "Mumbai, IN", "location_2": "London, UK", "distance_km": 7200, "time_delta_minutes": 45}),
        ("Impossible Travel", "HIGH", "Transaction from Delhi Device + Hyderabad ATM Same Time",
         {"location_1": "Delhi, IN", "location_2": "Hyderabad, ATM", "distance_km": 1250, "time_delta_minutes": 5}),
        ("Impossible Travel", "MEDIUM", "GPS Location Switch >500km Within Single Session",
         {"location_1": "Bangalore, IN", "location_2": "Chennai, IN", "distance_km": 350, "time_delta_minutes": 2}),
        # VPN Abuse
        ("VPN Abuse", "HIGH", "High-Risk Exit Node VPN During Fund Transfer",
         {"vpn_service": "NordVPN", "is_exit_node": True}),
        ("VPN Abuse", "MEDIUM", "Repeated VPN Connection Before Large Withdrawals",
         {"vpn_service": "ExpressVPN", "reconnection_count": 5}),
        # Fake Device
        ("Fake Device", "CRITICAL", "Emulator Farm: 50 Account Checks in 3 Minutes",
         {"is_emulator": True, "api_hits_per_minute": 17}),
        ("Fake Device", "HIGH", "Non-Existent Device Model in Fingerprint Database",
         {"unrecognized_hardware": True, "os_spoofing_detected": True}),
        # Location Spoofing
        ("Location Spoofing", "HIGH", "Mock GPS App Active During KYC Verification",
         {"mock_provider": "FakeGPS Free", "is_kyc_flow": True}),
        ("Location Spoofing", "MEDIUM", "Location Inconsistent With IP Geolocation",
         {"gps_country": "IN", "ip_country": "RU"})
    ]

    # status: Open(6), Investigating(5), Resolved(4)
    fraud_statuses = (["OPEN"] * 6) + (["INVESTIGATING"] * 5) + (["RESOLVED"] * 4)

    for i in range(15):
        f_num = f"FRD-202606{i+1:02d}-0001"
        f_type, risk, title, evidence_dict = fraud_titles[i]
        status = fraud_statuses[i]
        dev_id = random.choice(device_ids)
        assigned_to = user_id_map["fraud.analyst"] if random.random() < 0.6 else user_id_map["fraud.manager"]
        
        created_dt = datetime.datetime.now() - timedelta(days=random.randint(1, 15), hours=random.randint(0, 23))
        created_str = created_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        resolved_str = (created_dt + timedelta(hours=random.randint(12, 72))).strftime("%Y-%m-%d %H:%M:%S") if status == "RESOLVED" else None
        resolution_text = "Fraud risk mitigated. Customer account frozen and credentials reset." if status == "RESOLVED" else None

        cursor.execute("""
            INSERT INTO fraud_cases (
                case_number, device_id, fraud_type, risk_level, status, description, assigned_to, evidence, resolution, created_at, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f_num, dev_id, f_type, risk, status, title, assigned_to, json.dumps(evidence_dict), resolution_text, created_str, resolved_str
        ))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART H — COMPLIANCE REPORTS (6 reports)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[8/11] Seeding compliance reports...")
    reports_data = [
        ("RPT-RBI-202605", "Monthly Summary", "RBI", "2026-05-01", "2026-05-31",
         {"total_events": 412, "critical": 18, "clean_rate": 94.3, "blocked_devices": 7, "avg_risk_score": 43.2, "most_common_threat": "vpn_detected"}),
        ("RPT-PCI-202605", "Monthly Summary", "PCI-DSS", "2026-05-01", "2026-05-31",
         {"total_events": 284, "critical": 5, "clean_rate": 98.1, "blocked_devices": 2, "avg_risk_score": 21.4, "most_common_threat": "screenshot_detected"}),
        ("RPT-ISO-202605", "Monthly Summary", "ISO27001", "2026-05-01", "2026-05-31",
         {"total_events": 350, "critical": 10, "clean_rate": 96.5, "blocked_devices": 4, "avg_risk_score": 32.8, "most_common_threat": "vpn_detected"}),
        ("RPT-RBI-202604", "Monthly Summary", "RBI", "2026-04-01", "2026-04-30",
         {"total_events": 380, "critical": 15, "clean_rate": 95.0, "blocked_devices": 5, "avg_risk_score": 38.6, "most_common_threat": "root_detected"}),
        ("RPT-RBI-202606-W1", "Weekly Report", "RBI", "2026-06-01", "2026-06-07",
         {"total_events": 95, "critical": 3, "clean_rate": 96.8, "blocked_devices": 1, "avg_risk_score": 28.5, "most_common_threat": "vpn_detected"}),
        ("RPT-RBI-202606-W2", "Weekly Report", "RBI", "2026-06-08", "2026-06-14",
         {"total_events": 110, "critical": 6, "clean_rate": 93.2, "blocked_devices": 3, "avg_risk_score": 45.1, "most_common_threat": "frida_detected"})
    ]

    for rep_id, rep_type, std, start, end, s_data in reports_data:
        generated_by = user_id_map["compliance.mgr"]
        cursor.execute("""
            INSERT INTO compliance_reports (report_id, report_type, standard, period_start, period_end, generated_by, summary_data, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'GENERATED')
        """, (rep_id, rep_type, std, start, end, generated_by, json.dumps(s_data)))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART I — NOTIFICATIONS (20 notifications)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[9/11] Seeding notifications...")
    notifications_data = [
        # CRITICAL alerts (5, is_read=0)
        ("🚨 CRITICAL: Device ANDR-2024-F1R2D3 — Root + Frida detected. Immediate action required.", "CRITICAL", 0),
        ("🚨 CRITICAL: Coordinated attack detected. 8 devices showing simultaneous Frida activity.", "CRITICAL", 0),
        ("🚨 CRITICAL: Malware detected on corporate device IOS-2024-S1E2C4. Account suspended.", "CRITICAL", 0),
        ("🚨 CRITICAL: Device binding bypass attempt on high-value account holder device.", "CRITICAL", 0),
        ("🚨 CRITICAL: New CRITICAL incident created: INC-20260625-0001 — requires immediate review.", "CRITICAL", 0),
        # WARNING alerts (8, mix)
        ("⚠ HIGH: 12 devices detected using VPN during peak transaction hours.", "WARNING", 1),
        ("⚠ HIGH: App tampering detected on ANDR-2024-T1E2S3. Signature mismatch.", "WARNING", 0),
        ("⚠ WARNING: Compliance report RPT-RBI-202606 is due in 3 days.", "WARNING", 0),
        ("⚠ HIGH: Fraud case FRD-20260615-0015 escalated by fraud analyst — needs manager review.", "WARNING", 0),
        ("⚠ WARNING: Ollama LLM response time >5s. AI analysis may be delayed.", "WARNING", 1),
        ("⚠ HIGH: 3 devices blocked in last hour — possible coordinated attack.", "WARNING", 0),
        ("⚠ WARNING: API rate limit reached for device ANDR-2024-M4N5O6. Throttled.", "WARNING", 1),
        ("⚠ HIGH: New incident INC-20260624-0024 assigned to your team.", "WARNING", 0),
        # INFO alerts (7, is_read=1)
        ("✓ Compliance report RPT-RBI-202605 generated successfully.", "INFO", 1),
        ("✓ User soc.analyst logged in from 10.126.166.45.", "INFO", 1),
        ("✓ Database migration 007 applied successfully.", "INFO", 1),
        ("✓ Weekly security report ready for review.", "INFO", 1),
        ("✓ New user fraud.analyst created by sec.admin.", "INFO", 1),
        ("✓ Incident INC-20260618-0012 resolved by soc.analyst — closed.", "INFO", 1),
        ("✓ System health check passed. All services normal.", "INFO", 1)
    ]

    for msg, type_str, is_read in notifications_data:
        target_user = user_id_map["superadmin"] if random.random() < 0.5 else user_id_map["sec.admin"]
        dt = datetime.datetime.now() - timedelta(days=random.randint(0, 7), hours=random.randint(0, 23))
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (target_user, type_str + " Alert", msg, type_str, is_read, dt_str))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART J — API KEYS (2 keys)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[10/11] Seeding API keys...")
    key1_hash = hashlib.sha256(b"shield-demo-api-key-2024").hexdigest()
    key2_hash = hashlib.sha256(b"shield-admin-api-key-2024").hexdigest()

    cursor.execute("""
        INSERT OR REPLACE INTO api_keys (key_hash, label, is_active, rate_limit)
        VALUES (?, 'Flutter RASP App — Demo', 1, 100)
    """, (key1_hash,))
    cursor.execute("""
        INSERT OR REPLACE INTO api_keys (key_hash, label, is_active, rate_limit)
        VALUES (?, 'Admin Dashboard — Demo', 1, 500)
    """, (key2_hash,))
    conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PART K — DASHBOARD AUDIT LOGS (50 entries)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[11/11] Seeding dashboard audit logs...")
    audit_events = [
        # (action, module, details, role_needed)
        ("LOGIN", "AUTH", "Successful login from dashboard client", None),
        ("LOGOUT", "AUTH", "User initiated session logout", None),
        ("INCIDENT_CREATED", "INCIDENT", "New incident created for threat signal", "SOC_MANAGER"),
        ("INCIDENT_UPDATED", "INCIDENT", "Incident status changed to INVESTIGATING", "SOC_ANALYST"),
        ("USER_CREATED", "RBAC", "Created new user and assigned security permissions", "SUPER_ADMIN"),
        ("FRAUD_CASE_CREATED", "FRAUD", "New fraud case opened due to SIM Swap triggers", "FRAUD_MANAGER"),
        ("REPORT_GENERATED", "COMPLIANCE", "Compliance report generated for RBI standard review", "COMPLIANCE_MANAGER"),
        ("DEVICE_INVESTIGATION", "DEVICE", "Started forensic trace on suspected device", "SOC_ANALYST"),
        ("LOGIN_FAILED", "AUTH", "Failed password verification for user", None)
    ]

    ips = ["10.126.166.45", "10.126.166.89", "10.126.166.103", "192.168.1.100"]

    for _ in range(50):
        evt = random.choice(audit_events)
        action, module, base_details, role_filter = evt
        ip = random.choice(ips)
        dt = datetime.datetime.now() - timedelta(days=random.randint(0, 14), hours=random.randint(0, 23), minutes=random.randint(0, 59))
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")

        # Pick matching user
        if role_filter:
            target_user = user_id_map[list(user_id_map.keys())[list(role_id_map.keys()).index(role_filter)]]
        else:
            target_user = random.choice(list(user_id_map.values()))

        # Get name and role
        cursor.execute("SELECT username, role FROM dashboard_users WHERE id = ?", (target_user,))
        uinfo = cursor.fetchone()
        u_name = uinfo[0] if uinfo else "unknown"
        u_role = uinfo[1] if uinfo else "READ_ONLY_AUDITOR"

        if action == "LOGIN_FAILED":
            u_name = random.choice(["admin", "root", u_name])
            target_user = None
            details = f"{base_details} '{u_name}'"
        else:
            details = f"{base_details} ({u_name})"

        cursor.execute("""
            INSERT INTO dashboard_audit_logs (user_id, username, role, action, module, resource_id, ip_address, details, performed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (target_user, u_name, u_role, action, module, f"res_{random.randint(100,999)}", ip, details, dt_str))
    conn.commit()

    # Query counts for final summary
    cursor.execute("SELECT COUNT(*) FROM dashboard_users")
    cnt_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM device_security_profile")
    cnt_devices = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM threat_history")
    cnt_threats = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM risk_assessments")
    cnt_assess = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM incidents")
    cnt_inc = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fraud_cases")
    cnt_fraud = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM compliance_reports")
    cnt_reports = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT session_id) FROM security_chat_history")
    cnt_chat = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM notifications")
    cnt_notif = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM dashboard_audit_logs")
    cnt_audit = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM api_keys")
    cnt_keys = cursor.fetchone()[0]

    conn.close()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SUMMARY TABLE OUTPUT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\nSummary of Seeded Data:")
    print(f"[OK] Dashboard Users:    {cnt_users} created")
    print(f"[OK] Device Profiles:    {cnt_devices} created")
    print(f"[OK] Threat History:     {cnt_threats} records")
    print(f"[OK] Risk Assessments:   {cnt_assess} records")
    print(f"[OK] Incidents:          {cnt_inc} created")
    print(f"[OK] Fraud Cases:        {cnt_fraud} created")
    print(f"[OK] Compliance Reports: {cnt_reports} created")
    print(f"[OK] Chat History:       {cnt_chat} sessions")
    print(f"[OK] Notifications:      {cnt_notif} created")
    print(f"[OK] Audit Logs:         {cnt_audit} entries")
    print(f"[OK] API Keys:           {cnt_keys} created")

    print("\n" + "═"*40)
    print("DEMO DATA SEEDED SUCCESSFULLY")
    print("═"*40)
    print("Dashboard URL: http://10.166.170.103:8001/dashboard")
    print("\nLOGIN CREDENTIALS (all use password: Demo@1234)")
    print("─"*49)
    print("SUPER_ADMIN:        superadmin / Demo@1234")
    print("SECURITY_ADMIN:     sec.admin / Demo@1234")
    print("SOC_MANAGER:        soc.manager / Demo@1234")
    print("SOC_ANALYST:        soc.analyst / Demo@1234")
    print("FRAUD_MANAGER:      fraud.manager / Demo@1234")
    print("FRAUD_ANALYST:      fraud.analyst / Demo@1234")
    print("COMPLIANCE_MANAGER: compliance.mgr / Demo@1234")
    print("COMPLIANCE_OFFICER: compliance.off / Demo@1234")
    print("READ_ONLY_AUDITOR:  auditor / Demo@1234")
    print("\nTest each role to verify permission filtering works.")
    print("═"*40)

if __name__ == "__main__":
    main()
