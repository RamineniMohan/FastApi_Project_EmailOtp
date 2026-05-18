from datetime import datetime, timedelta, timezone
import secrets
from jose import jwt
from passlib.context import CryptContext
from core.config import settings

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
ALGORITHM = "HS256"

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) :
    return pwd_context.verify(plain, hashed)

def hash_text(text: str) :
    return pwd_context.hash(text)

def verify_text(plain: str, hashed: str)  :
    return pwd_context.verify(plain, hashed)

def generate_otp()  :
    return f"{secrets.randbelow(1000000):06d}"

def create_access_token(user_id: int, email: str) -> tuple[str, str, datetime]:
    jti = secrets.token_urlsafe(16)
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "email": email,
        "jti": jti,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
    return token, jti, expire

def decode_token(token: str):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])