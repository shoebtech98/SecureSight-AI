import logging
import os
from datetime import timedelta
from typing import Optional
from jose import JWTError, jwt

from backend.app.parsers.timeutil import utc_now

logger = logging.getLogger(__name__)

# ── Secret key handling ────────────────────────────────────────────────────
# The JWT signing key must never fall back to a committed default in a real
# deployment: anyone with access to the source could forge a token for any
# account. In a development environment an insecure fallback is allowed (with a
# loud warning); in any other environment a strong SECRET_KEY is mandatory or
# the application refuses to start.
ENV = os.getenv("ENV", "development").strip().lower()
_IS_DEV_ENV = ENV in {"dev", "development", "local", "test"}
_INSECURE_DEFAULT_KEY = "securesight_secret_key_change_me_in_production_1234567890"

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == _INSECURE_DEFAULT_KEY:
    if _IS_DEV_ENV:
        logger.warning(
            "SECRET_KEY is not set (ENV=%s) — using an insecure development key. "
            "Set a strong SECRET_KEY before deploying anywhere real.", ENV
        )
        SECRET_KEY = _INSECURE_DEFAULT_KEY
    else:
        raise RuntimeError(
            "SECRET_KEY must be set to a strong secret value when ENV=%r. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(64))"'
            % ENV
        )

ALGORITHM = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
REMEMBER_ME_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

import bcrypt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # A malformed or foreign hash in the database is a data-integrity issue,
        # not an ordinary wrong password. Fail the check closed, but log it
        # instead of silently swallowing every possible exception.
        logger.warning("verify_password: stored password hash is invalid or unreadable")
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# ── Security-answer hashing ────────────────────────────────────────────────
# Security answers were historically stored as normalized plaintext. They are
# now hashed with bcrypt like passwords. Legacy plaintext rows are still
# accepted on verification and upgraded to a hash on the next successful reset.
_BCRYPT_HASH_PREFIXES = ("$2a$", "$2b$", "$2y$")


def _normalize_security_answer(answer: str) -> str:
    # Case- and whitespace-insensitive: "  SecureSight AI " == "securesight ai".
    return (answer or "").strip().lower()


def hash_security_answer(answer: str) -> str:
    return get_password_hash(_normalize_security_answer(answer))


def security_answer_is_hashed(stored: Optional[str]) -> bool:
    return bool(stored) and stored.startswith(_BCRYPT_HASH_PREFIXES)


def verify_security_answer(answer: str, stored: Optional[str]) -> bool:
    if not stored:
        return False
    normalized = _normalize_security_answer(answer)
    if security_answer_is_hashed(stored):
        try:
            return bcrypt.checkpw(normalized.encode("utf-8"), stored.encode("utf-8"))
        except ValueError:
            logger.warning("verify_security_answer: stored answer hash is invalid or unreadable")
            return False
    # Legacy plaintext answer stored before answers were hashed.
    return normalized == stored


# Precomputed hash used only to equalize response time when an account does not
# exist, so /reset-password latency can't be used to tell which emails are
# registered. The wrapped value is irrelevant — it is never a real answer.
_DUMMY_SECURITY_ANSWER_HASH = get_password_hash("securesight-nonexistent-account-timing-guard")


def dummy_verify_security_answer(answer: str) -> None:
    """Run a throwaway verification so a missing account costs the same time."""
    verify_security_answer(answer, _DUMMY_SECURITY_ANSWER_HASH)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = utc_now() + expires_delta
    else:
        expire = utc_now() + timedelta(minutes=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
