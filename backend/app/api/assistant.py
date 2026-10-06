from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import LogEvent, LogFile, ThreatAlert, User, AiConversation, ChatMessage
from backend.app.schemas import ChatMessageCreate, ChatMessageResponse, AiConversationResponse
from backend.app.api.auth import get_current_user
from backend.app.services.gemini import call_gemini, GeminiError
from backend.app.parsers.timeutil import utc_now

router = APIRouter(prefix="/api/assistant", tags=["AI Assistant"])


def _user_alerts_query(db: Session, user_id: int):
    return (db.query(ThreatAlert)
            .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
            .join(LogFile, LogEvent.log_file_id == LogFile.id)
            .filter(LogFile.user_id == user_id))


@router.post("/query")
def query_assistant(payload: ChatMessageCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    question = payload.message.strip()
    if not question:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message cannot be empty.")

    files = (
        db.query(LogFile)
        .filter(LogFile.user_id == current_user.id)
        .order_by(LogFile.uploaded_at.desc())
        .limit(50)
        .all()
    )
    total_files = db.query(func.count(LogFile.id)).filter(LogFile.user_id == current_user.id).scalar() or 0

    # Aggregates only — never materialize the full event/alert tables.
    total_events = (
        db.query(func.count(LogEvent.id)).join(LogFile).filter(LogFile.user_id == current_user.id).scalar() or 0
    )
    alerts_query = _user_alerts_query(db, current_user.id)

    status_counts = dict(
        alerts_query.with_entities(ThreatAlert.status, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.status)
        .all()
    )
    severity_counts = dict(
        alerts_query.with_entities(ThreatAlert.severity, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.severity)
        .all()
    )
    type_rows = (
        alerts_query.with_entities(ThreatAlert.threat_type, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.threat_type)
        .all()
    )
    top_ip_rows = (
        alerts_query.with_entities(ThreatAlert.source_ip, func.count(ThreatAlert.id))
        .filter(ThreatAlert.source_ip != None)  # noqa: E711
        .group_by(ThreatAlert.source_ip)
        .order_by(func.count(ThreatAlert.id).desc())
        .limit(10)
        .all()
    )
    highest = (
        alerts_query.order_by(ThreatAlert.risk_score.desc(), ThreatAlert.timestamp.desc()).first()
    )
    recent_alerts = (
        alerts_query.order_by(ThreatAlert.timestamp.desc(), ThreatAlert.id.desc()).limit(15).all()
    )

    summary = {
        "total_events": total_events,
        "total_threats": sum(status_counts.values()),
        "active_threats": status_counts.get("active", 0),
        "critical_alerts": severity_counts.get("CRITICAL", 0),
        "high_alerts": severity_counts.get("HIGH", 0),
        "threat_type_counts": dict(type_rows),
        "top_ips": top_ip_rows,
        "highest_risk": highest,
    }

    context = {
        "file_count": total_files,
        "recent_files": [{"name": f.filename, "status": f.status} for f in files[:10]],
        "total_events": total_events,
        "total_threats": summary["total_threats"],
        "active_threats": summary["active_threats"],
        "critical_alerts": summary["critical_alerts"],
        "high_alerts": summary["high_alerts"],
        "threat_type_counts": summary["threat_type_counts"],
        "top_ips": [{"ip": ip, "alerts": count} for ip, count in top_ip_rows],
        "highest_risk": (
            {"type": highest.threat_type, "severity": highest.severity,
             "risk_score": highest.risk_score, "source_ip": highest.source_ip}
            if highest else None
        ),
        "recent_alerts": [
            {"type": a.threat_type, "severity": a.severity, "status": a.status,
             "risk_score": a.risk_score, "source_ip": a.source_ip}
            for a in recent_alerts
        ],
    }
    conversation_query = (
        db.query(AiConversation)
        .filter(AiConversation.user_id == current_user.id)
        .order_by(AiConversation.updated_at.desc())
    )
    if payload.conversation_id is not None:
        conversation = conversation_query.filter(AiConversation.id == payload.conversation_id).first()
        if conversation is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    else:
        conversation = conversation_query.first()

    if conversation:
        history = (
            db.query(ChatMessage)
            .filter(ChatMessage.conversation_id == conversation.id)
            .order_by(ChatMessage.id.desc())
            .limit(10)
            .all()
        )
        context["conversation_history"] = [
            {"role": message.role, "content": message.content[:2000]}
            for message in reversed(history)
        ]
    try:
        answer = call_gemini(question, context)
    except GeminiError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    if not conversation:
        conversation = AiConversation(title=question[:40], user_id=current_user.id)
        db.add(conversation)
        db.flush()

    user_msg = ChatMessage(role="user", content=question, conversation_id=conversation.id)
    ai_msg = ChatMessage(role="assistant", content=answer, conversation_id=conversation.id)
    db.add(user_msg)
    db.add(ai_msg)
    conversation.updated_at = utc_now()
    db.commit()

    return {
        "question": question,
        "answer": answer,
        "conversation_id": conversation.id,
        "files": [{"id": f.id, "filename": f.filename, "status": f.status, "uploaded_at": f.uploaded_at} for f in files],
        "event_count": total_events,
        "alert_count": sum(status_counts.values()),
        "matching_alerts": [
            {
                "id": a.id,
                "threat_type": a.threat_type,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "risk_score": a.risk_score,
                "timestamp": a.timestamp,
                "evidence": a.evidence,
            }
            for a in recent_alerts
        ],
        "source_ips": [{"ip": ip, "alerts": count} for ip, count in top_ip_rows],
        "highest_risk_alert": (
            {
                "id": highest.id,
                "threat_type": highest.threat_type,
                "severity": highest.severity,
                "source_ip": highest.source_ip,
                "risk_score": highest.risk_score,
                "timestamp": highest.timestamp,
            }
            if highest
            else None
        ),
    }


@router.get("/conversations", response_model=List[AiConversationResponse])
def get_user_conversations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(AiConversation).filter(AiConversation.user_id == current_user.id).order_by(AiConversation.updated_at.desc()).all()


@router.get("/conversations/latest", response_model=AiConversationResponse | None)
def get_latest_conversation(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (db.query(AiConversation).filter(AiConversation.user_id == current_user.id)
            .order_by(AiConversation.updated_at.desc()).first())


@router.delete("/conversations")
def clear_user_conversations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    conversation_ids = db.query(AiConversation.id).filter(AiConversation.user_id == current_user.id)
    db.query(ChatMessage).filter(ChatMessage.conversation_id.in_(conversation_ids)).delete(synchronize_session=False)
    db.query(AiConversation).filter(AiConversation.user_id == current_user.id).delete(synchronize_session=False)
    db.commit()
    return {"message": "Chat history cleared successfully"}
