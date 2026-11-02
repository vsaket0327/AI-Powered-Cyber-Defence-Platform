
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
import jwt
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()
load_dotenv(
    Path(__file__).resolve().parents[1] / ".env",
    override=False,
)
SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is missing. Configure it in your environment."
    )
if len(SECRET_KEY.encode("utf-8")) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY must contain at least 32 bytes."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        plain_password,
        hashed_password,
    )


def create_access_token(
    user_id: int,
    role: str,
) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )
