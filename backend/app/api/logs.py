import logging
from bisect import bisect_left, bisect_right
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.database import get_db
from backend.app.models import LogFile, LogEvent, ThreatAlert, CrossFileAlertSource, User
from backend.app.schemas import LogFileResponse
from backend.app.api.auth import get_current_user
from backend.app.parsers.log_parser import parse_log_content
from backend.app.detection.detection_engine import DetectionEngine
from backend.app.detection.correlation_engine import CorrelationEngine
from backend.app.services.normalizer import normalize_events

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/logs", tags=["Logs Ingestion"])

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_RECORD_CHARS = 256 * 1024
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}


def _contributes_to_correlation(old: dict, detection: dict, trigger: dict) -> bool:
    rule = detection["rule"]
    message = old["message"].lower()
    if rule == "repeated_failed_login":
        matches = old.get("source_ip") == detection.get("source_ip") and (
            "failed password" in message or "login failed" in message or
            "authentication failure" in message or old.get("event_type") == "windows_failed_login"
        )
        window = timedelta(minutes=5)
    elif rule == "port_scan":
        matches = old.get("source_ip") == detection.get("source_ip") and bool(old.get("destination_port"))
        window = timedelta(minutes=2)
    elif rule == "directory_reconnaissance":
        matches = old.get("source_ip") == detection.get("source_ip") and (
            old.get("status_code") == 404 or "404" in message
        )
        window = timedelta(minutes=10)
    elif rule == "suspicious_authentication":
        matches = (old.get("username") == detection.get("username") and
                   old.get("event_type") in {"login", "windows_login", "windows_failed_login"})
        window = timedelta(minutes=10)
    else:
        return False
    if not matches:
        return False
    return (old.get("timestamp") is not None and trigger.get("timestamp") is not None and
            abs(old["timestamp"] - trigger["timestamp"]) <= window)


def _cross_file_detections(db: Session, user_id: int, events: list[dict], current_detections: list[dict]) -> list[dict]:
    """Correlate this upload with the user's stored events near its timestamps."""
    timed = [event for event in events if event.get("timestamp") is not None]
    if not timed:
        return []
    source_ips = {event["source_ip"] for event in timed if event.get("source_ip")}
    usernames = {event["username"] for event in timed if event.get("username")}
    if not source_ips and not usernames:
        return []

    times = [event["timestamp"] for event in timed]
    margin = timedelta(minutes=10)
    owner_query = db.query(LogEvent).join(LogFile).filter(
        LogFile.user_id == user_id,
        LogEvent.timestamp >= min(times) - margin,
        LogEvent.timestamp <= max(times) + margin,
    )
    identity_filters = []
    if source_ips:
        identity_filters.append(LogEvent.source_ip.in_(source_ips))
    if usernames:
        identity_filters.append(LogEvent.username.in_(usernames))
    old_rows = owner_query.filter(or_(*identity_filters)).all()
    if not old_rows:
        return []
    old_events = [
        {"timestamp": row.timestamp, "message": row.message, "source_ip": row.source_ip,
         "username": row.username, "event_type": row.event_type,
         "destination_port": row.destination_port, "status_code": row.status_code,
         "log_file_id": row.log_file_id}
        for row in old_rows
    ]
    by_source = {}
    by_username = {}
    for old in old_events:
        if old["source_ip"]:
            by_source.setdefault(old["source_ip"], []).append(old)
        if old["username"]:
            by_username.setdefault(old["username"], []).append(old)
    for groups in (by_source, by_username):
        for identity, group in groups.items():
            group.sort(key=lambda event: event["timestamp"])
            groups[identity] = ([event["timestamp"] for event in group], group)

    correlator = CorrelationEngine()
    old_keys = {(item["rule"], item.get("source_ip"), item.get("username"))
                for item in correlator.correlate(old_events)}
    current_keys = {(item["rule"], item.get("source_ip"), item.get("username"))
                    for item in current_detections}
    found = []
    for item in correlator.correlate(old_events + events):
        key = (item["rule"], item.get("source_ip"), item.get("username"))
        if key in old_keys or key in current_keys or item["event_index"] < len(old_events):
            continue
        item["event_index"] -= len(old_events)
        event = events[item["event_index"]]
        detection = DetectionEngine._build_detection(
            item["rule"], item["threat_type"], event, item["event_index"],
            [item["evidence"]], "T1110" if item["rule"] == "repeated_failed_login" else "T1046",
            "Investigate the correlated activity and preserve the source events.", item,
        )
        if item["rule"] == "suspicious_authentication":
            times, candidates = by_username.get(item.get("username"), ([], []))
            window = timedelta(minutes=10)
        else:
            times, candidates = by_source.get(item.get("source_ip"), ([], []))
            window = timedelta(minutes={"port_scan": 2, "repeated_failed_login": 5}.get(item["rule"], 10))
        trigger_time = event.get("timestamp")
        if trigger_time is None:
            continue
        start = bisect_left(times, trigger_time - window)
        end = bisect_right(times, trigger_time + window)
        detection["source_file_ids"] = sorted({old["log_file_id"] for old in candidates[start:end]
                                                if _contributes_to_correlation(old, item, event)})
        if not detection["source_file_ids"]:
            continue
        found.append(detection)
    return found

@router.post("/upload", response_model=LogFileResponse)
def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    filename = file.filename or ""
    extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                            detail="Unsupported log format. Use .log, .txt, .csv, or .json files.")
    if len(filename) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in filename):
        raise HTTPException(status_code=400, detail="Invalid log filename.")

    # Read file content
    try:
        contents = file.file.read()
        file_size = len(contents)
        if file_size == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded log file is empty.")
        if file_size > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail="Log files must be 25 MB or smaller.")
        text_content = contents.decode("utf-8", errors="ignore")
        if any(len(line) > MAX_RECORD_CHARS for line in text_content.splitlines()):
            raise HTTPException(status_code=413, detail="A log record exceeds the 256 KB limit.")
    except HTTPException:
        raise
    except Exception:
        logger.exception("[Upload] Failed to read uploaded file %s", filename)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read the uploaded file. Please try again."
        )

    # 1. Create LogFile entry
    db_file = LogFile(
        filename=filename,
        file_size=file_size,
        status="processing",
        user_id=current_user.id
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    try:
        # 2. Parse log content
        events = parse_log_content(text_content)
        normalized_events = normalize_events(events)
        detections = DetectionEngine().analyze(normalized_events)
        detections.extend(_cross_file_detections(db, current_user.id, normalized_events, detections))
        detections_by_event = {}
        for detection in detections:
            event_index = detection["event_index"]
            detections_by_event.setdefault(event_index, []).append(detection)

        # 3. Create events (bulk insert for large files)
        db_events = []
        for event_index, ev in enumerate(normalized_events):
            event_detections = detections_by_event.get(event_index, [])
            if event_detections:
                ev["classification"] = event_detections[0]["rule"]
            db_events.append(LogEvent(
                timestamp=ev["timestamp"],
                service=ev["service"],
                level=ev["level"],
                message=ev["message"],
                ip_address=ev["ip_address"],
                source_ip=ev["source_ip"],
                destination_ip=ev["destination_ip"],
                hostname=ev["hostname"],
                port=ev["port"],
                destination_port=ev["destination_port"],
                protocol=ev["protocol"],
                username=ev["username"],
                event_type=ev["event_type"],
                action=ev["action"],
                event_status=ev["event_status"],
                method=ev["method"],
                path=ev["path"],
                status_code=ev["status_code"],
                classification=ev["classification"],
                log_file_id=db_file.id
            ))
        db.bulk_save_objects(db_events, return_defaults=True)

        # 4. Create threat alerts linked to the events
        db_alerts = []
        for alert in detections:
            event_idx = alert.get("event_index")
            linked_event_id = None
            if event_idx is not None and event_idx < len(db_events):
                linked_event_id = db_events[event_idx].id
            db_alerts.append(ThreatAlert(
                threat_type=alert["threat_type"],
                severity=alert["severity"],
                description=alert["description"],
                source_ip=alert["source_ip"],
                destination_ip=alert.get("destination_ip"),
                username=alert.get("username"),
                risk_score=alert["risk_score"],
                confidence=alert["confidence"],
                evidence=alert["evidence"],
                rule_triggered=alert["rule"],
                recommended_action=alert["recommended_action"],
                mitre_technique=alert.get("mitre_technique"),
                ai_summary=alert["ai_summary"],
                incident_summary=alert["incident_summary"],
                status="active",
                log_event_id=linked_event_id
            ))
        db.bulk_save_objects(db_alerts, return_defaults=True)
        cross_file_sources = []
        for detection, alert in zip(detections, db_alerts):
            for source_file_id in detection.get("source_file_ids", []):
                cross_file_sources.append(CrossFileAlertSource(alert_id=alert.id, log_file_id=source_file_id))
        if cross_file_sources:
            db.bulk_save_objects(cross_file_sources)

        db_file.status = "parsed"
        db.commit()
        db.refresh(db_file)
    except Exception:
        db.rollback()
        logger.exception("[Upload] Failed to parse log file %r", filename)

        db_file = db.query(LogFile).filter(LogFile.id == db_file.id).first()
        if db_file:
            db_file.status = "failed"
            db_file.error_message = "Parsing failed. The file may be empty, malformed, or unsupported."
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to parse the log file. Ensure it is a supported format."
        )

    return db_file

@router.get("/files", response_model=List[LogFileResponse])
def get_log_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(LogFile).filter(LogFile.user_id == current_user.id).order_by(LogFile.uploaded_at.desc()).all()

@router.delete("/files/{file_id}")
def delete_log_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id = current_user.id
    if db.bind.dialect.name == "sqlite":
        # The auth lookup has already used this session. End its read
        # transaction, then take the SQLite write lock before the owner check.
        db.rollback()
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    db_file = (db.query(LogFile)
               .filter(LogFile.id == file_id, LogFile.user_id == user_id)
               .with_for_update().first())
    if not db_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log file not found or unauthorized"
        )

    # Delete in dependency order with set-based SQL. The ORM cascade would load
    # every event and alert into memory (minutes for large files) and delete them
    # row-by-row, which times out the frontend request.
    event_ids = db.query(LogEvent.id).filter(LogEvent.log_file_id == file_id)
    linked_alert_ids = db.query(ThreatAlert.id).filter(ThreatAlert.log_event_id.in_(event_ids))
    contributed_alert_ids = db.query(CrossFileAlertSource.alert_id).filter(CrossFileAlertSource.log_file_id == file_id)
    alert_ids = {row[0] for row in linked_alert_ids.all()} | {row[0] for row in contributed_alert_ids.all()}
    if alert_ids:
        db.query(CrossFileAlertSource).filter(CrossFileAlertSource.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(ThreatAlert).filter(ThreatAlert.id.in_(alert_ids)).delete(synchronize_session=False)
    db.query(LogEvent).filter(LogEvent.log_file_id == file_id).delete(synchronize_session=False)
    deleted = db.query(LogFile).filter(LogFile.id == file_id, LogFile.user_id == user_id).delete(synchronize_session=False)
    if deleted != 1:
        db.rollback()
        raise HTTPException(status_code=404, detail="Log file not found or unauthorized")
    db.commit()
    return {"message": "Log file and all associated events deleted successfully"}

@router.get("/events")
def search_log_events(
    level: Optional[str] = None,
    service: Optional[str] = None,
    ip_address: Optional[str] = None,
    classification: Optional[str] = None,
    search: Optional[str] = Query(default=None, max_length=256),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Query must join LogFile to filter by user_id
    query = db.query(LogEvent).join(LogFile).filter(LogFile.user_id == current_user.id)

    if level:
        query = query.filter(LogEvent.level == level)
    if service:
        query = query.filter(LogEvent.service == service)
    if ip_address:
        query = query.filter((LogEvent.source_ip == ip_address) | (LogEvent.ip_address == ip_address))
    if classification:
        query = query.filter(LogEvent.classification == classification)
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        search_pattern = f"%{escaped}%"
        query = query.filter(
            (LogEvent.message.like(search_pattern, escape="\\")) |
            (LogEvent.path.like(search_pattern, escape="\\")) |
            (LogEvent.source_ip.like(search_pattern, escape="\\")) |
            (LogEvent.username.like(search_pattern, escape="\\")) |
            (LogEvent.service.like(search_pattern, escape="\\"))
        )


    # Get total count before pagination
    total_count = query.count()
    
    # Sort by timestamp desc (newest first)
    events = query.order_by(LogEvent.timestamp.desc(), LogEvent.id.desc()).offset(skip).limit(limit).all()

    # Format output explicitly
    events_data = []
    for ev in events:
        events_data.append({
            "id": ev.id,
            "timestamp": ev.timestamp,
            "service": ev.service,
            "level": ev.level,
            "message": ev.message,
            "ip_address": ev.ip_address,
            "source_ip": ev.source_ip or ev.ip_address,
            "destination_ip": ev.destination_ip,
            "hostname": ev.hostname,
            "port": ev.port,
            "destination_port": ev.destination_port,
            "protocol": ev.protocol,
            "username": ev.username,
            "event_type": ev.event_type,
            "action": ev.action,
            "event_status": ev.event_status,
            "method": ev.method,
            "path": ev.path,
            "status_code": ev.status_code,
            "classification": ev.classification,
            "log_file_id": ev.log_file_id
        })

    return {
        "total": total_count,
        "skip": skip,
        "limit": limit,
        "results": events_data
    }
