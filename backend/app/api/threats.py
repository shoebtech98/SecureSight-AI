from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional
from backend.app.database import get_db
from backend.app.models import ThreatAlert, LogFile, LogEvent, User
from backend.app.schemas import ThreatAlertResponse, ThreatAlertUpdate
from backend.app.api.auth import get_current_user

router = APIRouter(prefix="/api/threats", tags=["Threat Management"])

MAX_PAGE_LIMIT = 500


def _user_alerts_query(db: Session, user_id: int):
    """Base query scoped to the current user's alerts."""
    return (
        db.query(ThreatAlert)
        .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
        .join(LogFile, LogEvent.log_file_id == LogFile.id)
        .filter(LogFile.user_id == user_id)
    )


@router.get("", response_model=List[ThreatAlertResponse])
def get_threat_alerts(
    response: Response,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    limit = min(max(limit, 1), MAX_PAGE_LIMIT)
    skip = max(skip, 0)

    query = _user_alerts_query(db, current_user.id)
    if status:
        query = query.filter(ThreatAlert.status == status)
    if severity:
        query = query.filter(ThreatAlert.severity == severity)

    # Report the filtered total separately: the dashboard stats endpoint only
    # knows the unfiltered total, which would otherwise mislabel filtered pages.
    response.headers["X-Total-Count"] = str(query.count())

    # Order by timestamp desc, newest first
    alerts = (
        query.options(joinedload(ThreatAlert.log_event))
        .order_by(ThreatAlert.timestamp.desc(), ThreatAlert.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return alerts


@router.put("/{alert_id}", response_model=ThreatAlertResponse)
def update_threat_alert_status(
    alert_id: int,
    alert_in: ThreatAlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Fetch alert and verify authorization
    alert = (
        _user_alerts_query(db, current_user.id)
        .filter(ThreatAlert.id == alert_id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat alert not found or unauthorized"
        )

    # Validate status values
    valid_statuses = ["active", "resolved", "false_positive"]
    if alert_in.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status value. Must be one of {valid_statuses}"
        )

    alert.status = alert_in.status
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/stats")
def get_threat_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Two aggregate queries instead of seven: status counts and severity counts.
    status_rows = (
        _user_alerts_query(db, current_user.id)
        .with_entities(ThreatAlert.status, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.status)
        .all()
    )
    severity_rows = (
        _user_alerts_query(db, current_user.id)
        .with_entities(ThreatAlert.severity, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.severity)
        .all()
    )

    status_counts = dict(status_rows)
    severity_counts = dict(severity_rows)

    return {
        "total": sum(status_counts.values()),
        "active": status_counts.get("active", 0),
        "resolved": status_counts.get("resolved", 0),
        "false_positive": status_counts.get("false_positive", 0),
        "severity": {
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
        }
    }
