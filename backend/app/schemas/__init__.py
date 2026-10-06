import re
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime

# At least 8 characters with lowercase, uppercase, a digit, and a special character.
STRONG_PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$")
PASSWORD_POLICY_MSG = (
    "Password must be at least 8 characters and include an uppercase letter, "
    "a lowercase letter, a number, and a special character."
)


# bcrypt only hashes the first 72 bytes of a password and silently ignores the
# rest. Rather than hash a truncated value (which is surprising and weakens long
# passphrases), reject anything longer so the user gets a clear error.
MAX_PASSWORD_BYTES = 72


def validate_password_strength(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password must not exceed {MAX_PASSWORD_BYTES} bytes; "
            "bcrypt ignores anything beyond that length."
        )
    if not STRONG_PASSWORD_PATTERN.match(value):
        raise ValueError(PASSWORD_POLICY_MSG)
    return value

class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    security_question: str

class UserCreate(UserBase):
    password: str = Field(min_length=8)
    security_answer: str = Field(min_length=1, max_length=256)

    _validate_password = field_validator("password")(validate_password_strength)

class UserResponse(UserBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    security_answer: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8)

    _validate_password = field_validator("new_password")(validate_password_strength)

class Token(BaseModel):
    access_token: str
    token_type: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(default=None, min_length=8)
    security_question: Optional[str] = None
    security_answer: Optional[str] = Field(default=None, max_length=256)
    # Re-authentication: the account's *current* password, required by the route
    # whenever a sensitive field (password / email / security question or answer)
    # is being changed. Not strength-validated — it's an existing credential.
    current_password: Optional[str] = None

    _validate_password = field_validator("password")(validate_password_strength)

class UserUpdateResponse(UserResponse):
    """Profile update response; carries a fresh access token when the email changed."""
    access_token: Optional[str] = None

from typing import List, Dict, Any

# Log file and event schemas
class LogFileResponse(BaseModel):
    id: int
    filename: str
    file_size: int
    status: str
    error_message: Optional[str] = None
    uploaded_at: datetime
    user_id: int

    model_config = ConfigDict(from_attributes=True)

class LogEventResponse(BaseModel):
    id: int
    timestamp: Optional[datetime] = None
    service: Optional[str] = None
    level: str
    message: str
    ip_address: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    action: Optional[str] = None
    event_status: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    classification: str
    log_file_id: int

    model_config = ConfigDict(from_attributes=True)

# Threat alert schemas
class ThreatAlertResponse(BaseModel):
    id: int
    threat_type: str
    severity: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    risk_score: int = 0
    confidence: int = 0
    evidence: Optional[str] = None
    rule_triggered: Optional[str] = None
    recommended_action: Optional[str] = None
    mitre_technique: Optional[str] = None
    ai_summary: Optional[str] = None
    incident_summary: Optional[str] = None
    timestamp: datetime
    status: str
    log_event_id: Optional[int] = None
    log_event: Optional[LogEventResponse] = None

    model_config = ConfigDict(from_attributes=True)

class ThreatAlertUpdate(BaseModel):
    status: str  # active, resolved, false_positive

# Dashboard and alert summary schemas
class DashboardStatsResponse(BaseModel):
    total_events: int
    total_threats: int
    active_threats: int
    total_files: int
    recent_threats: List[ThreatAlertResponse]
    severity_distribution: List[Dict[str, Any]]
    alert_severity_distribution: List[Dict[str, Any]] = []
    threat_type_distribution: List[Dict[str, Any]]
    events_over_time: List[Dict[str, Any]]
    top_ips: List[Dict[str, Any]]
    critical_alerts: int = 0
    high_risk_ips: int = 0
    brute_force_attempts: int = 0
    sql_injection_attempts: int = 0
    malware_events: int = 0
    authentication_failures: int = 0
    threat_timeline: List[Dict[str, Any]] = []


# AI Assistant schemas
class ChatMessageCreate(BaseModel):
    # Bound the length so a single request can't persist an unbounded blob to the DB.
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: Optional[int] = None

class ChatMessageResponse(BaseModel):
    id: int
    role: str
    content: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class AiConversationResponse(BaseModel):
    id: int
    title: str
    created_at: datetime
    updated_at: datetime
    messages: List[ChatMessageResponse] = []

    model_config = ConfigDict(from_attributes=True)

