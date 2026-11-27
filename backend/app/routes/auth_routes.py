import re
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import mailer, ratelimit
from app.sessions import start_session
from app.auth import create_access_token, hash_password, verify_password
from app.database import get_db
from app.deps import ADMIN_EMAILS, get_client_ip, get_current_user
from app.logger import log_event
from app.models.message import Message
from app.models.user import User
from app.schemas import PublicKeyUpload, Token, UserCreate, UserLogin, UserOut

router = APIRouter()

TERMS_VERSION = "1.0"
MIN_PASSWORD_LENGTH = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,20}$")
RESERVED_USERNAMES = {"admin", "administrator", "root", "support", "system", "moderator", "staff", "security"}


@router.post("/register", response_model=UserOut)
def register(user: UserCreate, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)

    if not user.accept_terms:
        raise HTTPException(status_code=400, detail="You must agree to the rules to create an account.")

    username = user.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3 to 20 characters: letters, numbers, dots, dashes or underscores.",
        )
    if username.lower() in RESERVED_USERNAMES:
        raise HTTPException(status_code=400, detail="That username is not available.")
    if len(user.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    if db.query(User.id).filter(User.email == user.email).first():
        log_event(db, "register", status="failed", email=user.email, ip_address=ip)
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User.id).filter(func.lower(User.username) == username.lower()).first():
        raise HTTPException(status_code=400, detail="That username is already taken.")

    new_user = User(
        email=user.email,
        username=username,
        hashed_password=hash_password(user.password),
        role="admin" if user.email in ADMIN_EMAILS else "user",
        terms_accepted_at=datetime.now(timezone.utc),
        terms_version=TERMS_VERSION,
    )
    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        taken_email = db.query(User.id).filter(User.email == user.email).first()
        raise HTTPException(
            status_code=400,
            detail="Email already registered" if taken_email else "That username is already taken.",
        )

    db.refresh(new_user)
    log_event(db, "register", user_id=new_user.id, email=new_user.email, ip_address=ip)
    return new_user

@router.post("/login", response_model=Token)
def login(
    credentials: UserLogin,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    ip = get_client_ip(request)
    email_key = credentials.email.strip().lower()
    account_key = f"{ip}|{email_key}"
    ip_key = ip or "unknown"
    limiting = ratelimit.enabled()

    # Refuse the attempt outright if a limit has been hit (even a correct password is refused)
    if limiting:
        wait = max(
            ratelimit.account_limiter.retry_after(account_key),
            ratelimit.ip_limiter.retry_after(ip_key),
        )
        if wait:
            log_event(db, "login_blocked", status="blocked", email=credentials.email, ip_address=ip)
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed attempts. Try again in {wait} seconds.",
                headers={"Retry-After": str(wait)},
            )

    user = db.query(User).filter(User.email == credentials.email).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        if limiting:
            ratelimit.account_limiter.record_failure(account_key)
            ratelimit.ip_limiter.record_failure(ip_key)
        log_event(
            db, "login_failure", status="failed",
            user_id=user.id if user else None,
            email=credentials.email, ip_address=ip,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Only someone who knows the password learns the account is deactivated
    if not user.is_active:
        log_event(db, "login_denied", status="deactivated", user_id=user.id, email=user.email, ip_address=ip)
        raise HTTPException(
            status_code=403,
            detail="This account has been deactivated. Contact an administrator.",
        )

    ratelimit.account_limiter.clear(account_key)
    started = start_session(db, user, request, credentials.device_id)
    log_event(db, "login_success", user_id=user.id, email=user.email, ip_address=ip)

    if started["unfamiliar"]:
        log_event(db, "login_new_device", status=started["label"][:100], user_id=user.id,
                  email=user.email, ip_address=ip)
        background.add_task(
            mailer.send_email,
            user.email,
            "New sign-in to your account",
            f"Hello {user.username},\n\nYour account was just signed in to from a device we have not seen before:\n\n"
            f"  {started['label']}\n  Address: {started['ip'] or 'unknown'}\n\n"
            "If this was you, no action is needed. If it was not, open Security centre, sign out the unfamiliar "
            "session, and change your password.\n",
        )

    return {
        "access_token": create_access_token(data={"sub": user.email, "sid": started["sid"]}),
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
    }


@router.post("/upload-key")
def upload_key(
    key_data: PublicKeyUpload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current_user.public_key = key_data.public_key
    if key_data.signing_key:
        current_user.signing_key = key_data.signing_key
    db.commit()
    log_event(db, "key_upload", user_id=current_user.id, email=current_user.email,
              ip_address=get_client_ip(request))
    return {"message": "Public key uploaded successfully"}


@router.get("/users")
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Contacts, by username only. Emails are never returned here."""
    users = (
        db.query(User)
        .filter(User.public_key.isnot(None), User.is_active.is_(True))
        .all()
    )
    return [
        {"username": u.username, "public_key": u.public_key, "signing_key": u.signing_key}
        for u in users
    ]


@router.get("/messages")
def my_messages(
    limit: int = 500,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The caller's own conversation history, as ciphertext only, with usernames."""
    rows = (
        db.query(Message)
        .filter(or_(Message.sender_id == current_user.id, Message.receiver_id == current_user.id))
        .order_by(Message.id.desc())
        .limit(min(limit, 1000))
        .all()
    )
    rows.reverse()

    ids = {r.sender_id for r in rows} | {r.receiver_id for r in rows}
    names = {u.id: u.username for u in db.query(User).filter(User.id.in_(ids)).all()} if ids else {}

    return [
        {
            "from": names.get(r.sender_id),
            "to": names.get(r.receiver_id),
            "ciphertext": r.ciphertext,
            "nonce": r.nonce,
            "signature": r.signature,
            "msg_id": r.msg_id,
            "timestamp": r.timestamp,
            "delivered": r.delivered,
        }
        for r in rows
    ]


from app.routes.password_routes import router as password_router  # noqa: E402

router.include_router(password_router)