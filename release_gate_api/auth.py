"""JWT auth helpers for release-gate API."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

def _load_secret_key() -> str:
    """Resolve the JWT signing secret.

    The secret MUST come from the RG_JWT_SECRET environment variable in any
    real deployment. We deliberately do NOT ship a usable default — a
    hardcoded key in a public repo lets anyone forge an admin token and
    bypass authentication entirely.

    Only when running locally (no DATABASE_URL, i.e. the SQLite dev fallback)
    do we fall back to an ephemeral random key for developer convenience.
    """
    secret = os.environ.get("RG_JWT_SECRET", "").strip()
    if secret:
        return secret
    # Deployed (Postgres) environments must set the secret explicitly.
    if os.environ.get("DATABASE_URL"):
        raise RuntimeError(
            "RG_JWT_SECRET is not set. Refusing to start with a default signing "
            "key in a deployed environment — set RG_JWT_SECRET to a random 256-bit value."
        )
    # Local dev only: ephemeral per-process key (tokens won't survive restart).
    import secrets as _secrets
    return _secrets.token_urlsafe(48)


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, email: str, plan: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": user_id,
        "email": email,
        "plan": plan,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
