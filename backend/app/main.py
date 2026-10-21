from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base, SessionLocal
from app.models import user, message
from app.models.user import User
from app.models.message import Message
from app.routes import auth_routes
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


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        await websocket.close(code=1008)
        return

    db = SessionLocal()
    try:
        me = db.query(User).filter(User.email == email).first()
        if me is None:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        active_connections[email] = websocket

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

        while True:
            data = await websocket.receive_json()
            recipient = db.query(User).filter(User.email == data.get("to")).first()
            if recipient is None:
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
        db.close()