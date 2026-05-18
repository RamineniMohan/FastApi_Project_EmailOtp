from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from core.database import get_db
from models.users import User, RevokedToken
from schemas.user_schema import (
    RegisterRequest, VerifyOtpRequest, ResendOtpRequest,
    LoginRequest, ForgotPasswordRequest, ResetPasswordRequest,
    TokenResponse, MessageResponse
)
from utils.security import (
    hash_password, verify_password, hash_text, verify_text,
    generate_otp, create_access_token
)
from utils.emailer import send_email, build_otp_body, build_reset_body
from core.config import settings

router = APIRouter()

@router.post("/register", response_model=MessageResponse)
async def register(payload: RegisterRequest, background_tasks: BackgroundTasks,
                    db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already exists")

    otp = generate_otp()
    user = User(
        name=payload.name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        is_verified=False,
        otp_hash=hash_text(otp),
        otp_expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
    )
    db.add(user)
    await db.commit()

    background_tasks.add_task(
        send_email,
        payload.email,
        "Verify your email",
        build_otp_body(payload.name, otp),
    )
    return {"message": "Registered successfully. OTP sent to email."}

@router.post("/verify-otp", response_model=MessageResponse)
async def verify_otp(payload: VerifyOtpRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        return {"message": "Email already verified"}

    if not user.otp_hash or not user.otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP not available")

    if datetime.now(timezone.utc) > user.otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP expired")

    if not verify_text(payload.otp, user.otp_hash):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user.is_verified = True
    user.otp_hash = None
    user.otp_expires_at = None
    await db.commit()
    return {"message": "Email verified successfully"}

@router.post("/resend-otp", response_model=MessageResponse)
async def resend_otp(payload: ResendOtpRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified")

    otp = generate_otp()
    user.otp_hash = hash_text(otp)
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    await db.commit()

    background_tasks.add_task(
        send_email,
        user.email,
        "Your new verification OTP",
        build_otp_body(user.name, otp),
    )
    return {"message": "OTP resent successfully"}

@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")

    token, _, _ = create_access_token(user.id, user.email)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(payload: ForgotPasswordRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = generate_otp()
    user.reset_hash = hash_text(otp)
    user.reset_expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)
    await db.commit()

    background_tasks.add_task(
        send_email,
        user.email,
        "Password reset OTP",
        build_reset_body(user.name, otp),
    )
    return {"message": "Password reset OTP sent to email"}

@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.reset_hash or not user.reset_expires_at:
        raise HTTPException(status_code=400, detail="Reset OTP not available")

    if datetime.now(timezone.utc) > user.reset_expires_at:
        raise HTTPException(status_code=400, detail="Reset OTP expired")

    if not verify_text(payload.otp, user.reset_hash):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user.hashed_password = hash_password(payload.new_password)
    user.reset_hash = None
    user.reset_expires_at = None
    await db.commit()
    return {"message": "Password reset successfully"}

@router.post("/logout", response_model=MessageResponse)
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    payload = getattr(request.state, "token_payload", None)
    if not payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        raise HTTPException(status_code=400, detail="Invalid token")

    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    db.add(RevokedToken(jti=jti, expires_at=expires_at))
    await db.commit()
    return {"message": "Logged out successfully"}




# GET ALL USERS
@router.get("/users")
async def get_all_users(
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User))

    users = result.scalars().all()

    return users


# DELETE ACCOUNT
@router.delete("/delete-user/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(User).where(User.id == user_id)
    )

    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    await db.delete(user)
    await db.commit()

    return {
        "message": f"User with id {user_id} deleted successfully"
    }