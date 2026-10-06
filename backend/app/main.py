from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.models import user
from app.routes import auth_routes

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