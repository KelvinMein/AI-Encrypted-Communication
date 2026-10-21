from sqlalchemy import Column, Integer, String, Text, Boolean, BigInteger, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String, nullable=False)
    signature = Column(Text, nullable=False)
    msg_id = Column(String, nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    delivered = Column(Boolean, default=False, nullable=False)
    sent_at = Column(DateTime(timezone=True), server_default=func.now())