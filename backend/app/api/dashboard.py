from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload
from backend.app.database import get_db
from backend.app.models import LogFile, LogEvent, ThreatAlert, User
from backend.app.schemas import DashboardStatsResponse
from backend.app.api.auth import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard Analytics"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_files = (
        db.query(func.count(LogFile.id)).filter(LogFile.user_id == current_user.id).scalar() or 0
    )

    empty_stats = {
        "total_events": 0,
        "total_threats": 0,
        "active_threats": 0,
        "total_files": 0,
        "recent_threats": [],
        "severity_distribution": [],
        "alert_severity_distribution": [],
        "threat_type_distribution": [],
        "events_over_time": [],
        "top_ips": [],
        "critical_alerts": 0,
        "high_risk_ips": 0,
        "brute_force_attempts": 0,
        "sql_injection_attempts": 0,
        "malware_events": 0,
        "authentication_failures": 0,
        "threat_timeline": [],
    }
    if total_files == 0:
        return empty_stats

    # Subquery representing the user's log file IDs, pushed into SQL.
    user_file_subquery = db.query(LogFile.id).filter(LogFile.user_id == current_user.id)

    total_events = (
        db.query(func.count(LogEvent.id))
        .filter(LogEvent.log_file_id.in_(user_file_subquery))
        .scalar() or 0
    )

    # Alerts scoped to the user's files, ready for aggregation.
    alerts = (
        db.query(ThreatAlert)
        .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
        .filter(LogEvent.log_file_id.in_(user_file_subquery))
    )

    # Status, severity and threat-type distributions in three GROUP BY queries.
    status_counts = dict(
        alerts.with_entities(ThreatAlert.status, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.status)
        .all()
    )
    severity_counts = dict(
        alerts.with_entities(ThreatAlert.severity, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.severity)
        .all()
    )
    type_rows = (
        alerts.with_entities(ThreatAlert.threat_type, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.threat_type)
        .all()
    )
    threat_type_distribution = [{"name": name, "value": count} for name, count in type_rows]

    # Alert-severity distribution in a stable CRITICAL -> INFO order.
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    alert_severity_distribution = [
        {"name": name, "value": severity_counts.get(name, 0)}
        for name in SEVERITY_ORDER
        if severity_counts.get(name, 0) > 0
    ]

    # Derived counters from the threat-type distribution (single query reused).
    def type_count(*needles):
        return sum(count for name, count in type_rows if any(n in name for n in needles))

    recent_threats = (
        alerts.options(joinedload(ThreatAlert.log_event))
        .order_by(ThreatAlert.timestamp.desc())
        .limit(5)
        .all()
    )

    severity_rows = (
        db.query(LogEvent.level, func.count(LogEvent.id))
        .filter(LogEvent.log_file_id.in_(user_file_subquery))
        .group_by(LogEvent.level)
        .all()
    )
    severity_distribution = [{"name": name, "value": count} for name, count in severity_rows]

    timeline_rows = (
        db.query(func.date(LogEvent.timestamp), func.count(LogEvent.id))
        .filter(LogEvent.log_file_id.in_(user_file_subquery))
        .filter(LogEvent.timestamp != None)  # noqa: E711
        .group_by(func.date(LogEvent.timestamp))
        .order_by(func.date(LogEvent.timestamp).desc())
        .limit(15)
        .all()
    )
    timeline_rows.reverse()
    events_over_time = [{"date": date, "events": count} for date, count in timeline_rows]

    top_ips = [
        {"ip": ip, "count": count}
        for ip, count in (
            alerts.with_entities(ThreatAlert.source_ip, func.count(ThreatAlert.id))
            .filter(ThreatAlert.source_ip != None)  # noqa: E711
            .group_by(ThreatAlert.source_ip)
            .order_by(func.count(ThreatAlert.id).desc())
            .limit(5)
            .all()
        )
    ]

    # Timeline grouped by the *source event* date so threats line up with the
    # events that triggered them, rather than the alert generation date.
    selected_dates = [date for date, _ in timeline_rows]
    threat_dates = (
        db.query(func.date(LogEvent.timestamp), func.count(ThreatAlert.id))
        .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
        .filter(LogEvent.log_file_id.in_(user_file_subquery),
                func.date(LogEvent.timestamp).in_(selected_dates))
        .group_by(func.date(LogEvent.timestamp))
        .order_by(func.date(LogEvent.timestamp).asc())
        .all()
    )
    threat_timeline = [{"date": date, "threats": count} for date, count in threat_dates]

    high_risk_ips = (
        db.query(func.count(func.distinct(ThreatAlert.source_ip)))
        .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
        .filter(
            LogEvent.log_file_id.in_(user_file_subquery),
            ThreatAlert.risk_score >= 50,
            ThreatAlert.source_ip != None,  # noqa: E711
        )
        .scalar() or 0
    )

    return {
        "total_events": total_events,
        "total_threats": sum(status_counts.values()),
        "active_threats": status_counts.get("active", 0),
        "total_files": total_files,
        "recent_threats": recent_threats,
        "severity_distribution": severity_distribution,
        "alert_severity_distribution": alert_severity_distribution,
        "threat_type_distribution": threat_type_distribution,
        "events_over_time": events_over_time,
        "top_ips": top_ips,
        "critical_alerts": severity_counts.get("CRITICAL", 0),
        "high_risk_ips": high_risk_ips,
        "brute_force_attempts": type_count("Brute Force"),
        "sql_injection_attempts": type_count("SQL Injection"),
        "malware_events": type_count("Malware"),
        "authentication_failures": type_count("Authentication"),
        "threat_timeline": threat_timeline,
    }
