from app.models.metadata_log import MetadataLog
from app import detector


def log_event(db, event_type, status="ok", user_id=None, email=None,
              ip_address=None, size_bytes=None, recipient_email=None):
    """Records one metadata event, then scores it. Never stores message content.
    Neither logging nor scoring may ever break the real request, so errors are swallowed."""
    try:
        entry = MetadataLog(
            user_id=user_id,
            email=email,
            event_type=event_type,
            status=status,
            ip_address=ip_address,
            size_bytes=size_bytes,
            recipient_email=recipient_email,
        )
        db.add(entry)
        db.commit()
        log_id = entry.id
    except Exception:
        db.rollback()
        return

    try:
        detector.check_event(db, log_id, event_type, email)
    except Exception as e:
        db.rollback()
        print(f"[detector] skipped: {e}")