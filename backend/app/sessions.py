import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from app.auth import ACCESS_TOKEN_EXPIRE_MINUTES
from app.deps import get_client_ip
from app.models.session import SecurityNotification, UserSession


def describe_device(ua: str) -> str:
    ua = ua or ""
    if "Edg/" in ua:
        browser = "Edge"
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Chrome/" in ua:
        browser = "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = "Unknown browser"

    if "Windows" in ua:
        system = "Windows"
    elif "Android" in ua:           # before Linux: Android reports itself as Linux too
        system = "Android"
    elif "iPhone" in ua or "iPad" in ua:  # before macOS: iOS reports "like Mac OS X"
        system = "iOS"
    elif "Mac OS X" in ua:
        system = "macOS"
    elif "Linux" in ua:
        system = "Linux"
    else:
        system = "Unknown system"
    return f"{browser} on {system}"


def start_session(db, user, request, device_id):
    """Creates a session for a successful login and says whether the device is unfamiliar."""
    ua = request.headers.get("user-agent", "")
    device_key = f"d:{device_id[:64]}" if device_id else "ua:" + hashlib.sha256(ua.encode()).hexdigest()[:16]
    label = describe_device(ua)
    ip = get_client_ip(request)

    had_sessions = db.query(UserSession.id).filter(UserSession.user_id == user.id).first() is not None
    known = (
        db.query(UserSession.id)
        .filter(
            UserSession.user_id == user.id,
            UserSession.device_key == device_key,
            UserSession.confirmed.is_(True),
        )
        .first()
        is not None
    )
    confirmed = known or not had_sessions  # the very first login is trusted by definition

    sid = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    db.add(
        UserSession(
            user_id=user.id, sid=sid, device_key=device_key, device_label=label, ip_address=ip,
            confirmed=confirmed, expires_at=now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
    )
    if not confirmed:
        db.add(
            SecurityNotification(
                user_id=user.id, kind="new_device",
                message=f"New sign-in from {label} ({ip or 'unknown address'}).",
            )
        )
    db.commit()
    return {"sid": sid, "unfamiliar": not confirmed, "label": label, "ip": ip}