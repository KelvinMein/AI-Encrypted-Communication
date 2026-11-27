from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from sqlalchemy import func

from app.auth import ALGORITHM, SECRET_KEY
from app.connections import active_connections, session_sockets
from app.database import Base, SessionLocal, engine
from app.logger import log_event
from app.models import message as _message  # noqa: F401  (registers the tables)
from app.models import metadata_log as _metadata_log  # noqa: F401
from app.models import report as _report  # noqa: F401
from app.models import user as _user  # noqa: F401
from app.models import session as _session  # noqa: F401
from app.models.session import UserSession
from app.models.message import Message
from app.models.user import User
from app.routes import admin_routes, auth_routes, report_routes, session_routes

app = FastAPI(title="AI-Encrypted Communication System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)
app.include_router(auth_routes.router)
app.include_router(report_routes.router)
app.include_router(admin_routes.router)
app.include_router(session_routes.router)


@app.get("/")
def root():
    return {"message": "Backend is running"}


def build_payload(msg: Message, sender_username: str, offline: bool):
    return {
        "from": sender_username,
        "ciphertext": msg.ciphertext,
        "nonce": msg.nonce,
        "signature": msg.signature,
        "msg_id": msg.msg_id,
        "timestamp": msg.timestamp,
        "offline": offline,
    }


def ciphertext_size(b64: str) -> int:
    return int(len(b64 or "") * 3 / 4)


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    ip = websocket.client.host if websocket.client else None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        sid = payload.get("sid")
    
    except JWTError:
        bad_db = SessionLocal()
        log_event(bad_db, "ws_rejected", status="failed", ip_address=ip)
        bad_db.close()
        await websocket.close(code=1008)
        return

    db = SessionLocal()
    try:
        me = db.query(User).filter(User.email == email).first()
        if me is None or not me.is_active:
            log_event(db, "ws_rejected", status="failed", email=email, ip_address=ip)
            await websocket.close(code=1008)
            return
        sess = (
            db.query(UserSession).filter(UserSession.sid == sid, UserSession.user_id == me.id).first()
            if sid else None
        )
        if sess is None or sess.revoked:
            log_event(db, "ws_rejected", status="session_ended", email=email, ip_address=ip)
            await websocket.close(code=1008)
            return
        await websocket.accept()
        session_sockets[sid] = websocket
        active_connections[email] = websocket
        log_event(db, "ws_connect", user_id=me.id, email=email, ip_address=ip)

        # Deliver anything that arrived while this user was offline
        pending = (
            db.query(Message)
            .filter(Message.receiver_id == me.id, Message.delivered == False)  # noqa: E712
            .order_by(Message.id)
            .all()
        )
        for m in pending:
            sender = db.query(User).filter(User.id == m.sender_id).first()
            await websocket.send_json(build_payload(m, sender.username, offline=True))
            m.delivered = True
        db.commit()
        if pending:
            log_event(db, "offline_delivery", status=f"{len(pending)} delivered",
                      user_id=me.id, email=email, ip_address=ip)

        while True:
            data = await websocket.receive_json()

            db.refresh(me)
            if not me.is_active:  # deactivated while connected
                await websocket.close(code=1008)
                break

            to_name = str(data.get("to") or "").strip().lower()
            recipient = (
                db.query(User).filter(func.lower(User.username) == to_name).first() if to_name else None
            )
            if recipient is None or not recipient.is_active or recipient.id == me.id:
                log_event(db, "message_failed", status="unknown_recipient", user_id=me.id,
                          email=email, ip_address=ip, recipient_email=to_name)
                continue

            # Always store the ciphertext first (the server never sees plaintext)
            msg = Message(
                sender_id=me.id,
                receiver_id=recipient.id,
                ciphertext=data.get("ciphertext"),
                nonce=data.get("nonce"),
                signature=data.get("signature"),
                msg_id=data.get("msg_id"),
                timestamp=data.get("timestamp"),
                delivered=False,
            )
            db.add(msg)
            db.commit()

            # Metadata only: who, to whom, how big. Never the content.
            log_event(db, "message_sent", user_id=me.id, email=email, ip_address=ip,
                      recipient_email=recipient.email, size_bytes=ciphertext_size(data.get("ciphertext")))

            recipient_ws = active_connections.get(recipient.email)
            if recipient_ws:
                try:
                    await recipient_ws.send_json(build_payload(msg, me.username, offline=False))
                    msg.delivered = True
                    db.commit()
                except Exception:
                    active_connections.pop(recipient.email, None)
    except WebSocketDisconnect:
        pass
    finally:
        if active_connections.get(email) is websocket:
            active_connections.pop(email, None)
            log_event(db, "ws_disconnect", email=email, ip_address=ip)
        if session_sockets.get(sid) is websocket:
            session_sockets.pop(sid, None)
        db.close()