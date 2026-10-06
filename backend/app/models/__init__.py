from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.app.database import Base
from backend.app.parsers.timeutil import utc_now

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    security_question = Column(String, nullable=False)
    security_answer = Column(String, nullable=False)  # bcrypt hash of the normalized answer (legacy rows may be plaintext)
    created_at = Column(DateTime, default=utc_now)

    # Relationships
    log_files = relationship("LogFile", back_populates="user", cascade="all, delete-orphan")
    ai_conversations = relationship("AiConversation", back_populates="user", cascade="all, delete-orphan")

class LogFile(Base):
    __tablename__ = "log_files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_size = Column(Integer, nullable=False)
    status = Column(String, default="processing")  # processing, parsed, failed
    error_message = Column(String, nullable=True)
    uploaded_at = Column(DateTime, default=utc_now)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="log_files")
    events = relationship("LogEvent", back_populates="log_file", cascade="all, delete-orphan")

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=True, index=True)
    service = Column(String, nullable=True)      # e.g. sshd, nginx, system
    level = Column(String, default="INFO")       # INFO, WARN, ERROR, CRITICAL
    message = Column(Text, nullable=False)
    ip_address = Column(String, nullable=True)
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    username = Column(String, nullable=True)
    event_type = Column(String, nullable=True)
    action = Column(String, nullable=True)
    event_status = Column(String, nullable=True)
    method = Column(String, nullable=True)       # GET, POST
    path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    classification = Column(String, default="clean") # clean, brute_force, sql_injection, xss, port_scan
    log_file_id = Column(Integer, ForeignKey("log_files.id", ondelete="CASCADE"), nullable=False, index=True)

    # Relationships
    log_file = relationship("LogFile", back_populates="events")
    threats = relationship("ThreatAlert", back_populates="log_event", cascade="all, delete-orphan")

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String, nullable=False)  # Brute Force, SQL Injection, XSS, etc.
    severity = Column(String, nullable=False)     # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(String, nullable=False)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    username = Column(String, nullable=True)
    risk_score = Column(Integer, default=0, nullable=False)
    confidence = Column(Integer, default=0, nullable=False)
    evidence = Column(Text, nullable=True)
    rule_triggered = Column(String, nullable=True)
    recommended_action = Column(Text, nullable=True)
    mitre_technique = Column(String, nullable=True)
    ai_summary = Column(Text, nullable=True)
    incident_summary = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    status = Column(String, default="active")     # active, resolved, false_positive
    log_event_id = Column(Integer, ForeignKey("log_events.id", ondelete="CASCADE"), nullable=True, index=True)

    # Relationships
    log_event = relationship("LogEvent", back_populates="threats")


class CrossFileAlertSource(Base):
    """Files whose events contributed to a cross-file correlation alert."""
    __tablename__ = "cross_file_alert_sources"

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("threat_alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    log_file_id = Column(Integer, ForeignKey("log_files.id", ondelete="CASCADE"), nullable=False, index=True)


class AiConversation(Base):
    __tablename__ = "ai_conversations"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, default="New Security Analysis Session")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    user = relationship("User", back_populates="ai_conversations")
    messages = relationship("ChatMessage", back_populates="conversation", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    role = Column(String, nullable=False)  # user or assistant
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=utc_now)
    conversation_id = Column(Integer, ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)

    conversation = relationship("AiConversation", back_populates="messages")

