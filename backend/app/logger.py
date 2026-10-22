from app.models.metadata_log import MetadataLog


def log_event(db, event_type, status="ok", user_id=None, email=None,
              ip_address=None, size_bytes=None, recipient_email=None):
    """Records one metadata event. Never stores message content.
    A logging failure must never break the real request, so errors are swallowed."""
    try:
        db.add(MetadataLog(
            user_id=user_id,
            email=email,
            event_type=event_type,
            status=status,
            ip_address=ip_address,
            size_bytes=size_bytes,
            recipient_email=recipient_email,
        ))
        db.commit()
    except Exception:
        db.rollback()