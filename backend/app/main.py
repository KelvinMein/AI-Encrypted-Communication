from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.models import user
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

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    active_connections[email] = websocket

    try:
        while True:
            data = await websocket.receive_json()
            recipient_email = data.get("to")
            recipient_ws = active_connections.get(recipient_email)

            if recipient_ws:
                await recipient_ws.send_json({
                    "from": email,
                    "ciphertext": data.get("ciphertext"),
                    "nonce": data.get("nonce"),
                    "signature": data.get("signature"),
                })
    except WebSocketDisconnect:
        active_connections.pop(email, None)