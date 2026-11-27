from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)   # private: never shown to other users
    username = Column(String, nullable=False)                         # the public name
    hashed_password = Column(String, nullable=False)
    public_key = Column(String, nullable=True)
    signing_key = Column(String, nullable=True)
    role = Column(String, nullable=False, default="user", server_default="user")  # "user" or "admin"
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    deactivated_reason = Column(Text, nullable=True)
    terms_accepted_at = Column(DateTime(timezone=True), nullable=True)
    terms_version = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# Usernames are unique ignoring case, so "Kelvin" cannot impersonate "kelvin"
Index("ix_users_username_lower", func.lower(User.username), unique=True)