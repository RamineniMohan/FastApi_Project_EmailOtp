from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sqlalchemy import select
from core.database import AsyncSessionLocal
from models.users import RevokedToken
from utils.security import decode_token

PUBLIC_PATHS = [
    "/register",
    "/verify-otp",
    "/resend-otp",
    "/login",
    "/forgot-password",
    "/reset-password",
    "/docs",
    "/openapi.json",
    "/redoc",

    "/users",
    "/delete-user",
]
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # allow public routes
        if any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS):
            return await call_next(request)

        # allow preflight
        if request.method == "OPTIONS":
            return await call_next(request)

        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Not authenticated"}
            )

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = decode_token(token)
            if not payload:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid token"}
                )
        except Exception:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token"}
            )

        jti = payload.get("jti")
        sub = payload.get("sub")

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(RevokedToken).where(RevokedToken.jti == jti)
            )
            if result.scalar_one_or_none():
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Token revoked"}
                )

        request.state.user_id = int(sub)
        request.state.token_payload = payload
        return await call_next(request)