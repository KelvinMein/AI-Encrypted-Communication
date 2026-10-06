from fastapi import FastAPI
from app.database import engine, Base
from app.models import user
from app.routes import auth_routes

app = FastAPI(title="AI-Encrypted Communication System")

Base.metadata.create_all(bind=engine)

app.include_router(auth_routes.router)

@app.get("/")
def root():
    return {"message": "Backend is running"}