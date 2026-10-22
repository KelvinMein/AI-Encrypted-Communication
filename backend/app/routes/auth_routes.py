from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from jose import jwt, JWTError

from app.database import get_db
from app.models.user import User
from app.models.metadata_log import MetadataLog
from app.schemas import UserCreate, UserOut, UserLogin, Token, PublicKeyUpload
from app.auth import hash_password, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from app.logger import log_event

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_client_ip(request: Request):
    return request.client.host if request.client else None


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


@router.post("/register", response_model=UserOut)
def register(user: UserCreate, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    hashed_pw = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw)

    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        log_event(db, "register", status="failed", email=user.email, ip_address=ip)
        raise HTTPException(status_code=400, detail="Email already registered")

    db.refresh(new_user)
    log_event(db, "register", user_id=new_user.id, email=new_user.email, ip_address=ip)
    return new_user


@router.post("/login", response_model=Token)
def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    user = db.query(User).filter(User.email == credentials.email).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        log_event(
            db, "login_failure", status="failed",
            user_id=user.id if user else None,
            email=credentials.email, ip_address=ip,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    log_event(db, "login_success", user_id=user.id, email=user.email, ip_address=ip)
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


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
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.public_key.isnot(None)).all()
    return [
        {"email": u.email, "public_key": u.public_key, "signing_key": u.signing_key}
        for u in users
    ]


@router.get("/logs")
def list_logs(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Any logged-in user can read this for now; it will be restricted to an
    # administrator role when the admin dashboard is built.
    rows = (
        db.query(MetadataLog)
        .order_by(MetadataLog.id.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [
        {
            "id": r.id,
            "event_type": r.event_type,
            "status": r.status,
            "email": r.email,
            "recipient_email": r.recipient_email,
            "ip_address": r.ip_address,
            "size_bytes": r.size_bytes,
            "occurred_at": r.occurred_at.isoformat() if r.occurred_at else None,
        }
        for r in rows
    ]