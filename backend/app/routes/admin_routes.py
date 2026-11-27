from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.connections import active_connections
from app.database import get_db
from app.deps import require_admin
from app.logger import log_event
from app.models.anomaly_flag import AnomalyFlag
from app.models.metadata_log import MetadataLog
from app.models.report import Report
from app.models.user import User

router = APIRouter()


class Note(BaseModel):
    note: Optional[str] = None


class Reason(BaseModel):
    reason: Optional[str] = None


class RoleChange(BaseModel):
    role: str


def _iso(t):
    return t.isoformat() if t else None


# ---------- security alerts and activity log ----------

@router.get("/logs")
def list_logs(limit: int = 50, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(MetadataLog).order_by(MetadataLog.id.desc()).limit(min(limit, 500)).all()
    return [
        {
            "id": r.id, "event_type": r.event_type, "status": r.status, "email": r.email,
            "recipient_email": r.recipient_email, "ip_address": r.ip_address,
            "size_bytes": r.size_bytes, "occurred_at": _iso(r.occurred_at),
        }
        for r in rows
    ]


@router.get("/flags")
def list_flags(limit: int = 100, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(AnomalyFlag).order_by(AnomalyFlag.id.desc()).limit(min(limit, 500)).all()
    return [
        {
            "id": r.id, "subject": r.subject, "email": r.email, "anomaly_score": r.anomaly_score,
            "reason": r.reason, "reviewed": r.reviewed, "flagged_at": _iso(r.flagged_at),
        }
        for r in rows
    ]


@router.post("/flags/{flag_id}/review")
def review_flag(flag_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    flag = db.query(AnomalyFlag).filter(AnomalyFlag.id == flag_id).first()
    if flag is None:
        raise HTTPException(status_code=404, detail="Flag not found")
    flag.reviewed = True
    db.commit()
    return {"message": "Flag marked as reviewed"}


# ---------- people ----------

@router.get("/admin/users")
def admin_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    total = dict(db.query(Report.reported_id, func.count(Report.id)).group_by(Report.reported_id).all())
    opened = dict(
        db.query(Report.reported_id, func.count(Report.id))
        .filter(Report.status == "open")
        .group_by(Report.reported_id)
        .all()
    )
    users = db.query(User).order_by(User.id).all()
    return [
        {
            "id": u.id, "username": u.username, "email": u.email, "role": u.role,
            "is_active": u.is_active, "deactivated_reason": u.deactivated_reason,
            "created_at": _iso(u.created_at),
            "open_reports": opened.get(u.id, 0), "total_reports": total.get(u.id, 0),
        }
        for u in users
    ]


@router.post("/admin/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int, body: Reason, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")
    if target.role == "admin":
        raise HTTPException(status_code=400, detail="Administrator accounts cannot be deactivated. Change the role first.")

    reason = (body.reason or "").strip()[:300] or "Deactivated by an administrator"
    target.is_active = False
    target.deactivated_reason = reason
    db.query(Report).filter(Report.reported_id == target.id, Report.status == "open").update(
        {
            "status": "actioned",
            "resolved_by_id": admin.id,
            "resolved_at": datetime.now(timezone.utc),
            "resolution_note": f"Account deactivated: {reason}",
        },
        synchronize_session=False,
    )
    db.commit()

    # End any live session straight away
    ws = active_connections.pop(target.email, None)
    if ws is not None:
        try:
            await ws.close(code=1008)
        except Exception:
            pass

    log_event(db, "admin_deactivate", status=reason[:100], user_id=admin.id, email=admin.email,
              recipient_email=target.email)
    return {"message": f"{target.username} has been deactivated."}


@router.post("/admin/users/{user_id}/reactivate")
def reactivate_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = True
    target.deactivated_reason = None
    db.commit()
    log_event(db, "admin_reactivate", user_id=admin.id, email=admin.email, recipient_email=target.email)
    return {"message": f"{target.username} has been reactivated."}


@router.post("/admin/users/{user_id}/role")
def change_role(
    user_id: int, body: RoleChange, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    if body.role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Role must be user or admin.")
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot change your own role.")
    target.role = body.role
    db.commit()
    log_event(db, "admin_role_change", status=body.role, user_id=admin.id, email=admin.email,
              recipient_email=target.email)
    return {"message": f"{target.username} is now {body.role}."}


# ---------- reports ----------

@router.get("/admin/reports")
def list_reports(status: str = "open", admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(Report)
    if status != "all":
        q = q.filter(Report.status == status)
    rows = q.order_by(Report.id.desc()).limit(200).all()

    ids = {r.reporter_id for r in rows} | {r.reported_id for r in rows}
    users = {u.id: u for u in db.query(User).filter(User.id.in_(ids)).all()} if ids else {}
    totals = dict(db.query(Report.reported_id, func.count(Report.id)).group_by(Report.reported_id).all())

    return [
        {
            "id": r.id, "status": r.status, "reason": r.reason, "details": r.details,
            "evidence_text": r.evidence_text, "created_at": _iso(r.created_at),
            "reporter": users[r.reporter_id].username,
            "reported": users[r.reported_id].username,
            "reported_user_id": r.reported_id,
            "reported_active": users[r.reported_id].is_active,
            "reported_total": totals.get(r.reported_id, 0),
            "resolution_note": r.resolution_note, "resolved_at": _iso(r.resolved_at),
        }
        for r in rows
    ]


@router.post("/admin/reports/{report_id}/dismiss")
def dismiss_report(
    report_id: int, body: Note, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "open":
        raise HTTPException(status_code=400, detail="This report has already been resolved.")
    report.status = "dismissed"
    report.resolved_by_id = admin.id
    report.resolved_at = datetime.now(timezone.utc)
    report.resolution_note = (body.note or "").strip()[:300] or "Dismissed"
    db.commit()
    log_event(db, "admin_dismiss_report", user_id=admin.id, email=admin.email)
    return {"message": "Report dismissed."}