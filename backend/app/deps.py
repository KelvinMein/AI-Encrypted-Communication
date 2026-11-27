import os
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.auth import ALGORITHM, SECRET_KEY  # importing app.auth also loads backend/.env
from app.database import get_db
from app.models.session import UserSession
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Emails that become administrators when they register. Compared exactly as written.
ADMIN_EMAILS = {e.strip() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()}


def get_client_ip(request: Request):
    return request.client.host if request.client else None


def get_auth(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """The caller's user and session. A token whose session has ended is refused."""
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        sid = payload.get("sid")
        if email is None or sid is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:  # checked on every request, so deactivation takes effect immediately
        raise HTTPException(status_code=403, detail="This account has been deactivated.")

    session = db.query(UserSession).filter(UserSession.sid == sid, UserSession.user_id == user.id).first()
    if session is None or session.revoked:
        raise HTTPException(status_code=401, detail="This session has ended. Please log in again.")

    now = datetime.now(timezone.utc)
    if session.last_seen_at is None or (now - session.last_seen_at).total_seconds() > 60:
        session.last_seen_at = now  # recorded at most once a minute
        db.commit()
    return user, session


def get_current_user(auth=Depends(get_auth)):
    return auth[0]


def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return current_user