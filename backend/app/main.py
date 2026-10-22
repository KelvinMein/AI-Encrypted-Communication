from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base, SessionLocal
from app.models import user, message, metadata_log
from app.models.user import User
from app.models.message import Message
from app.routes import auth_routes
from app.logger import log_event
from jose import jwt, JWTError
from app.auth import SECRET_KEY, ALGORITHM

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

@app.get("/")
def root():
    return {"message": "Backend is running"}

# Keeps track of which email is connected on which active WebSocket
active_connections: dict[str, WebSocket] = {}


def build_payload(msg: Message, sender_email: str, offline: bool):
    return {
        "from": sender_email,
        "ciphertext": msg.ciphertext,
        "nonce": msg.nonce,
        "signature": msg.signature,
        "msg_id": msg.msg_id,
        "timestamp": msg.timestamp,
        "offline": offline,
    }


def ciphertext_size(b64: str) -> int:
    # Approximate decoded size in bytes from the Base64 text length
    return int(len(b64 or "") * 3 / 4)


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    ip = websocket.client.host if websocket.client else None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        bad_db = SessionLocal()
        log_event(bad_db, "ws_rejected", status="failed", ip_address=ip)
        bad_db.close()
        await websocket.close(code=1008)
        return

    db = SessionLocal()
    try:
        me = db.query(User).filter(User.email == email).first()
        if me is None:
            log_event(db, "ws_rejected", status="failed", email=email, ip_address=ip)
            await websocket.close(code=1008)
            return

        await websocket.accept()
        active_connections[email] = websocket
        log_event(db, "ws_connect", user_id=me.id, email=email, ip_address=ip)

        # Deliver anything that arrived while this user was offline
        pending = (
            db.query(Message)
            .filter(Message.receiver_id == me.id, Message.delivered == False)
            .order_by(Message.id)
            .all()
        )
        for m in pending:
            sender = db.query(User).filter(User.id == m.sender_id).first()
            await websocket.send_json(build_payload(m, sender.email, offline=True))
            m.delivered = True
        db.commit()
        if pending:
            log_event(db, "offline_delivery", status=f"{len(pending)} delivered",
                      user_id=me.id, email=email, ip_address=ip)

        while True:
            data = await websocket.receive_json()
            recipient = db.query(User).filter(User.email == data.get("to")).first()
            if recipient is None:
                log_event(db, "message_failed", status="unknown_recipient",
                          user_id=me.id, email=email, ip_address=ip,
                          recipient_email=data.get("to"))
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
            log_event(db, "message_sent", user_id=me.id, email=email,
                      ip_address=ip, recipient_email=recipient.email,
                      size_bytes=ciphertext_size(data.get("ciphertext")))

            # If the recipient is online, deliver now and mark it delivered
            recipient_ws = active_connections.get(recipient.email)
            if recipient_ws:
                try:
                    await recipient_ws.send_json(build_payload(msg, email, offline=False))
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
        db.close()