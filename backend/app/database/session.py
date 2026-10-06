import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from .base import Base


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./securesight.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

is_sqlite = DATABASE_URL.startswith("sqlite")
is_postgres = DATABASE_URL.startswith("postgresql+psycopg://")
if not (is_sqlite or is_postgres):
    raise ValueError("DATABASE_URL must be a SQLite or PostgreSQL connection URL.")

# connect_args={"check_same_thread": False} is required only for SQLite
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if is_sqlite else {"sslmode": "require"},
    **({"pool_pre_ping": True, "pool_size": 3, "max_overflow": 2} if is_postgres else {}),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def ensure_schema():
    """Add legacy SIEM columns and indexes on SQLite and PostgreSQL."""
    additions = {
        "log_events": {
            "source_ip": "VARCHAR", "destination_ip": "VARCHAR", "hostname": "VARCHAR", "port": "INTEGER",
            "destination_port": "INTEGER", "protocol": "VARCHAR", "username": "VARCHAR", "event_type": "VARCHAR",
            "action": "VARCHAR", "event_status": "VARCHAR"
        },
        "threat_alerts": {
            "destination_ip": "VARCHAR", "username": "VARCHAR", "risk_score": "INTEGER DEFAULT 0",
            "confidence": "INTEGER DEFAULT 0", "evidence": "TEXT", "rule_triggered": "VARCHAR",
            "recommended_action": "TEXT", "mitre_technique": "VARCHAR", "ai_summary": "TEXT", "incident_summary": "TEXT"
        }
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
        for index_name, table, column in (
            ("ix_log_files_user_id", "log_files", "user_id"),
            ("ix_log_events_log_file_id", "log_events", "log_file_id"),
            ("ix_log_events_source_ip", "log_events", "source_ip"),
            ("ix_log_events_ip_address", "log_events", "ip_address"),
            ("ix_log_events_timestamp", "log_events", "timestamp"),
            ("ix_log_events_level", "log_events", "level"),
            ("ix_log_events_classification", "log_events", "classification"),
            ("ix_threat_alerts_log_event_id", "threat_alerts", "log_event_id"),
            ("ix_threat_alerts_source_ip", "threat_alerts", "source_ip"),
            ("ix_threat_alerts_timestamp", "threat_alerts", "timestamp"),
            ("ix_threat_alerts_severity", "threat_alerts", "severity"),
            ("ix_threat_alerts_status", "threat_alerts", "status"),
        ):
            connection.execute(text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({column})"))

# Dependency to get db session in FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
