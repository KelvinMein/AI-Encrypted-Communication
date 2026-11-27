
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app import mailer, ratelimit
from app.auth import hash_password
from app.database import get_db
from app.logger import log_event
from app.models.password_reset import PasswordReset
from app.models.session import SecurityNotification, UserSession
from app.models.user import User

router = APIRouter()

RESET_MINUTES = 15
MIN_PASSWORD_LENGTH = 8
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
GENERIC_REPLY = "If an account exists for that email, a reset link has been sent. It expires in 15 minutes."

# Requests per email and address, requests per address overall, and bad token guesses per address
reset_limiter = ratelimit.FailureLimiter(max_failures=5, window_seconds=900)
reset_ip_limiter = ratelimit.FailureLimiter(max_failures=20, window_seconds=900)
bad_token_limiter = ratelimit.FailureLimiter(max_failures=10, window_seconds=900)


class ForgotPassword(BaseModel):
    email: EmailStr


class ResetPassword(BaseModel):
    token: str
    new_password: str


def _ip(request: Request):
    return request.client.host if request.client else None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _too_many(wait: int, what: str):
    return HTTPException(
        status_code=429,
        detail=f"Too many {what}. Try again in {wait} seconds.",
        headers={"Retry-After": str(wait)},
    )


@router.post("/forgot-password")
def forgot_password(
    body: ForgotPassword,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    ip = _ip(request)
    key = f"{ip}|{body.email.strip().lower()}"

    # Applied to every request, whether or not the account exists, so it reveals nothing
    if ratelimit.enabled():
        wait = max(reset_limiter.retry_after(key), reset_ip_limiter.retry_after(ip or "unknown"))
        if wait:
            raise _too_many(wait, "reset requests")
        reset_limiter.record_failure(key)
        reset_ip_limiter.record_failure(ip or "unknown")

    user = db.query(User).filter(User.email == body.email).first()
    if user:
        # An earlier unused link stops working as soon as a new one is requested
        db.query(PasswordReset).filter(
            PasswordReset.user_id == user.id, PasswordReset.used.is_(False)
        ).update({"used": True}, synchronize_session=False)

        token = secrets.token_urlsafe(32)
        db.add(
            PasswordReset(
                user_id=user.id,
                token_hash=_hash(token),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_MINUTES),
            )
        )
        db.commit()

        link = f"{FRONTEND_URL}/?reset={token}"
        text = (
            "Hello,\n\n"
            "We received a request to reset the password for your Secure Messenger account.\n\n"
            f"Choose a new password here. The link works once and expires in {RESET_MINUTES} minutes:\n"
            f"{link}\n\n"
            "If you did not ask for this, ignore this message. Your password will not change.\n"
        )
        background.add_task(mailer.send_email, user.email, "Reset your Secure Messenger password", text)
        log_event(db, "password_reset_requested", user_id=user.id, email=user.email, ip_address=ip)
    else:
        log_event(db, "password_reset_requested", status="unknown_email", email=body.email, ip_address=ip)

    return {"message": GENERIC_REPLY}


@router.post("/reset-password")
def reset_password(body: ResetPassword, request: Request, db: Session = Depends(get_db)):
    ip = _ip(request)
    ip_key = ip or "unknown"

    if ratelimit.enabled():
        wait = bad_token_limiter.retry_after(ip_key)
        if wait:
            raise _too_many(wait, "failed attempts")

    if len(body.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    row = db.query(PasswordReset).filter(PasswordReset.token_hash == _hash(body.token)).first()
    now = datetime.now(timezone.utc)
    if row is None or row.used or row.expires_at <= now:
        if ratelimit.enabled():
            bad_token_limiter.record_failure(ip_key)
        log_event(db, "password_reset_failed", status="invalid_token", ip_address=ip)
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    user = db.query(User).filter(User.id == row.user_id).first()
    user.hashed_password = hash_password(body.new_password)
    db.query(PasswordReset).filter(
        PasswordReset.user_id == user.id, PasswordReset.used.is_(False)
    ).update({"used": True}, synchronize_session=False)

    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked.is_(False)
    ).update(
        {"revoked": True}, synchronize_session=False
    )

    db.add(
        SecurityNotification(
            user_id=user.id, kind="password_reset",
            message="Your password was reset. Every device was signed out.",
        )
    )
    db.commit()

    # The person is no longer locked out of the account they have just recovered
    ratelimit.account_limiter.clear(f"{ip}|{user.email.strip().lower()}")
    log_event(db, "password_reset_completed", user_id=user.id, email=user.email, ip_address=ip)
    return {"message": "Password updated. You can log in now."}
