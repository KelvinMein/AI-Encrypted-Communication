from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base


class AnomalyFlag(Base):
    __tablename__ = "anomaly_flags"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("metadata_logs.id"), nullable=True)
    subject = Column(String, nullable=False, index=True)   # an email, or "network"
    email = Column(String, nullable=True)                  # the account whose event triggered it
    anomaly_score = Column(Float, nullable=False)          # Isolation Forest score (lower = stranger)
    reason = Column(Text, nullable=False)
    features = Column(Text, nullable=True)                 # the 10-second feature snapshot, as JSON
    reviewed = Column(Boolean, default=False, nullable=False)
    flagged_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)