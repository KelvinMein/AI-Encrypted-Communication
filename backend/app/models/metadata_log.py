from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base

class MetadataLog(Base):
    __tablename__ = "metadata_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    email = Column(String, nullable=True)            # the email involved, even if no account matched
    event_type = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="ok")
    ip_address = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)      # ciphertext size for message events
    recipient_email = Column(String, nullable=True)
    occurred_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)