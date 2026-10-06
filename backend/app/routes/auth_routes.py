from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from jose import jwt, JWTError

from app.database import get_db
from app.models.user import User
from app.schemas import UserCreate, UserOut, UserLogin, Token, PublicKeyUpload
from app.auth import hash_password, verify_password, create_access_token, SECRET_KEY, ALGORITHM

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


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
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_pw = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw)

    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")

    db.refresh(new_user)
    return new_user


@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == credentials.email).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/upload-key")
def upload_key(
    key_data: PublicKeyUpload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current_user.public_key = key_data.public_key
    db.commit()
    return {"message": "Public key uploaded successfully"}


@router.get("/users")
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.public_key.isnot(None)).all()
    return [{"email": u.email, "public_key": u.public_key} for u in users]