# app/utils/crypto.py
import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from passlib.context import CryptContext

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
_vault_key: bytes | None = None

def _get_secrets_dir() -> Path:
    # Keeps secrets folder in ./data/secrets relative to backend run root
    base_dir = Path(__file__).resolve().parent.parent.parent / "data" / "secrets"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir

def load_or_create_vault_key() -> bytes:
    global _vault_key
    if _vault_key is not None:
        return _vault_key

    secrets_dir = _get_secrets_dir()
    key_path = secrets_dir / "master_vault.key"

    if key_path.exists():
        _vault_key = key_path.read_bytes()
    else:
        # Generate new 256-bit URL-safe key
        _vault_key = Fernet.generate_key()
        key_path.write_bytes(_vault_key)
        # Restrict permissions on Unix/Linux systems (ignored on Windows)
        try:
            os.chmod(str(key_path), 0o600)
        except Exception:
            pass

    return _vault_key

def encrypt_secret(plain_text: str) -> str:
    """Encrypt a plain text secret (e.g. TOTP secret) using the vault key."""
    key = load_or_create_vault_key()
    fernet = Fernet(key)
    return fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")

def decrypt_secret(cipher_text: str) -> str:
    """Decrypt a ciphertext secret using the vault key."""
    key = load_or_create_vault_key()
    fernet = Fernet(key)
    return fernet.decrypt(cipher_text.encode("utf-8")).decode("utf-8")

def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate list of 8 recovery backup codes (each 8 hex characters)."""
    return [secrets.token_hex(4) for _ in range(count)]

def hash_backup_code(code: str) -> str:
    """Hash a backup code using bcrypt for safe database storage."""
    return _pwd_ctx.hash(code)

def verify_backup_code(code: str, hashed_code: str) -> bool:
    """Verify a backup code against its stored bcrypt hash."""
    try:
        return _pwd_ctx.verify(code, hashed_code)
    except Exception:
        return False
