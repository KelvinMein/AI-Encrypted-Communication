from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.connections import active_connections, session_sockets
from app.database import get_db
from app.deps import get_auth
from app.logger import log_event
from app.models.session import SecurityNotification, UserSession

router = APIRouter()


async def _close_socket(sid: str, email: str):
    ws = session_sockets.pop(sid, None)
    if ws is not None:
        if active_connections.get(email) is ws:
            active_connections.pop(email, None)
        try:
            await ws.close(code=1008)
        except Exception:
            pass


def _mine(db, user, session_id):
    row = db.query(UserSession).filter(UserSession.id == session_id, UserSession.user_id == user.id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return row


@router.get("/sessions")
def list_sessions(auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, current = auth
    rows = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.revoked.is_(False),
            UserSession.expires_at > datetime.now(timezone.utc),
        )
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    return [
        {
            "id": s.id, "device": s.device_label, "ip": s.ip_address, "confirmed": s.confirmed,
            "current": s.sid == current.sid,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "last_seen": s.last_seen_at.isoformat() if s.last_seen_at else None,
        }
        for s in rows
    ]


@router.post("/sessions/{session_id}/confirm")
def confirm_session(session_id: int, auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, _ = auth
    row = _mine(db, user, session_id)
    row.confirmed = True
    db.commit()
    return {"message": "Thanks. This device is now trusted."}


@router.post("/sessions/{session_id}/revoke")
async def revoke_session(session_id: int, auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, current = auth
    row = _mine(db, user, session_id)
    if row.sid == current.sid:
        raise HTTPException(status_code=400, detail="This is the session you are using. Use Log out instead.")
    row.revoked = True
    db.commit()
    await _close_socket(row.sid, user.email)
    log_event(db, "session_revoked", user_id=user.id, email=user.email)
    return {"message": "That session has been signed out."}


@router.post("/sessions/revoke-others")
async def revoke_others(auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, current = auth
    rows = (
        db.query(UserSession)
        .filter(UserSession.user_id == user.id, UserSession.revoked.is_(False), UserSession.sid != current.sid)
        .all()
    )
    for row in rows:
        row.revoked = True
    db.commit()
    for row in rows:
        await _close_socket(row.sid, user.email)
    log_event(db, "sessions_revoked_others", status=f"{len(rows)} signed out", user_id=user.id, email=user.email)
    return {"message": f"Signed out {len(rows)} other session{'s' if len(rows) != 1 else ''}."}


@router.post("/logout")
async def logout(auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, current = auth
    current.revoked = True
    db.commit()
    await _close_socket(current.sid, user.email)
    log_event(db, "logout", user_id=user.id, email=user.email)
    return {"message": "Signed out."}


@router.get("/security/notifications")
def notifications(auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, _ = auth
    items = (
        db.query(SecurityNotification)
        .filter(SecurityNotification.user_id == user.id)
        .order_by(SecurityNotification.id.desc())
        .limit(20)
        .all()
    )
    unconfirmed = (
        db.query(UserSession.id)
        .filter(
            UserSession.user_id == user.id,
            UserSession.revoked.is_(False),
            UserSession.confirmed.is_(False),
            UserSession.expires_at > datetime.now(timezone.utc),
        )
        .count()
    )
    return {
        "unread": sum(1 for i in items if not i.read),
        "unconfirmed": unconfirmed,
        "items": [
            {"id": i.id, "kind": i.kind, "message": i.message, "read": i.read, "created_at": i.created_at.isoformat()}
            for i in items
        ],
    }


@router.post("/security/notifications/read")
def mark_read(auth=Depends(get_auth), db: Session = Depends(get_db)):
    user, _ = auth
    db.query(SecurityNotification).filter(
        SecurityNotification.user_id == user.id, SecurityNotification.read.is_(False)
    ).update({"read": True}, synchronize_session=False)
    db.commit()
    return {"message": "Marked as read."}