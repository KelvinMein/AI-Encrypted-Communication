from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.sql import func

from app.database import Base


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("reporter_id", "msg_id", name="uq_report_once_per_message"),)

    id = Column(Integer, primary_key=True, index=True)
    reporter_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    reported_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    msg_id = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    evidence_text = Column(Text, nullable=True)   # supplied by the reporter; the server cannot verify it
    status = Column(String, nullable=False, default="open", index=True)  # open, dismissed, actioned
    resolution_note = Column(Text, nullable=True)
    resolved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())