from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_client_ip, get_current_user
from app.logger import log_event
from app.models.message import Message
from app.models.report import Report
from app.models.user import User

router = APIRouter()

REASONS = {"insult", "threat", "scam", "inappropriate", "other"}
MAX_REPORTS_PER_HOUR = 5


class ReportCreate(BaseModel):
    msg_id: str
    reason: str
    details: Optional[str] = None
    evidence_text: Optional[str] = None


@router.post("/reports")
def create_report(
    body: ReportCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.reason not in REASONS:
        raise HTTPException(status_code=400, detail="Choose a reason for the report.")

    # The server cannot read messages, but it can check that this message was really
    # sent to the reporter, so nobody can report a message they never received.
    msg = (
        db.query(Message)
        .filter(Message.msg_id == body.msg_id, Message.receiver_id == current_user.id)
        .order_by(Message.id)
        .first()
    )
    if msg is None:
        raise HTTPException(status_code=400, detail="You can only report messages that were sent to you.")
    if msg.sender_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot report yourself.")

    if db.query(Report.id).filter(Report.reporter_id == current_user.id, Report.msg_id == body.msg_id).first():
        raise HTTPException(status_code=400, detail="You have already reported this message.")

    since = datetime.now(timezone.utc) - timedelta(hours=1)
    recent = (
        db.query(func.count(Report.id))
        .filter(Report.reporter_id == current_user.id, Report.created_at >= since)
        .scalar()
    )
    if recent >= MAX_REPORTS_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail="You have sent several reports in the last hour. Please try again later.",
        )

    db.add(
        Report(
            reporter_id=current_user.id,
            reported_id=msg.sender_id,
            msg_id=body.msg_id,
            reason=body.reason,
            details=(body.details or "").strip()[:500] or None,
            evidence_text=(body.evidence_text or "").strip()[:1000] or None,
        )
    )
    db.commit()
    log_event(db, "report_submitted", user_id=current_user.id, email=current_user.email,
              ip_address=get_client_ip(request))
    return {"message": "Report sent. An administrator will review it."}