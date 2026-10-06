"""Performance benchmark for SecureSight AI endpoints.

Seeds an isolated SQLite database with a synthetic dataset (configurable size)
and times the endpoints that were reported slow. Run with an isolated DB:

    cd backend && DATABASE_URL="sqlite:///./perf.db" python -m tests.perf_benchmark 100000 20000
"""
import os
import sys
import time

import sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from fastapi.testclient import TestClient


def seed(db_path: str, n_events: int, n_alerts: int):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS log_events")
    cur.execute("DROP TABLE IF EXISTS log_files")
    cur.execute("DROP TABLE IF EXISTS threat_alerts")
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, hashed_password TEXT, full_name TEXT, security_question TEXT, security_answer TEXT, created_at TIMESTAMP)"
    )
    cur.execute(
        "CREATE TABLE log_files (id INTEGER PRIMARY KEY, filename TEXT, file_size INTEGER, status TEXT, error_message TEXT, uploaded_at TIMESTAMP, user_id INTEGER)"
    )
    cur.execute(
        "CREATE TABLE log_events (id INTEGER PRIMARY KEY, timestamp TIMESTAMP, service TEXT, level TEXT, message TEXT, ip_address TEXT, source_ip TEXT, destination_ip TEXT, hostname TEXT, port INTEGER, destination_port INTEGER, protocol TEXT, username TEXT, event_type TEXT, action TEXT, event_status TEXT, method TEXT, path TEXT, status_code INTEGER, classification TEXT, log_file_id INTEGER)"
    )
    cur.execute(
        "CREATE TABLE threat_alerts (id INTEGER PRIMARY KEY, threat_type TEXT, severity TEXT, description TEXT, source_ip TEXT, destination_ip TEXT, username TEXT, risk_score INTEGER, confidence INTEGER, evidence TEXT, rule_triggered TEXT, recommended_action TEXT, mitre_technique TEXT, ai_summary TEXT, incident_summary TEXT, timestamp TIMESTAMP, status TEXT, log_event_id INTEGER)"
    )
    cur.execute("CREATE INDEX ix_log_events_log_file_id ON log_events(log_file_id)")
    cur.execute("CREATE INDEX ix_log_events_source_ip ON log_events(source_ip)")
    cur.execute("CREATE INDEX ix_log_events_timestamp ON log_events(timestamp)")
    cur.execute("CREATE INDEX ix_threat_alerts_log_event_id ON threat_alerts(log_event_id)")
    cur.execute("CREATE INDEX ix_threat_alerts_timestamp ON threat_alerts(timestamp)")
    cur.execute("CREATE INDEX ix_threat_alerts_source_ip ON threat_alerts(source_ip)")
    cur.execute(
        "INSERT INTO users VALUES (1, 'perf@example.com', 'x', 'Perf User', 'q', 'a', '2026-01-01')"
    )
    cur.execute(
        "INSERT INTO log_files VALUES (1, 'perf.log', 0, 'parsed', NULL, '2026-01-01', 1)"
    )
    print(f"Seeding {n_events} events and {n_alerts} alerts...")
    cur.executemany(
        "INSERT INTO log_events (timestamp, service, level, message, source_ip, ip_address, classification, log_file_id) VALUES (?, 'sshd', 'INFO', ?, ?, ?, 'clean', 1)",
        [
            (
                f"2026-07-{20 + i % 9:02d} {10 + (i // 3600) % 12:02d}:{i % 60:02d}:{(i * 7) % 60:02d}",
                f"session opened for user u{i % 200}",
                f"10.0.{i % 50}.{i % 250}",
                f"10.0.{i % 50}.{i % 250}",
            )
            for i in range(n_events)
        ],
    )
    cur.executemany(
        "INSERT INTO threat_alerts (threat_type, severity, description, source_ip, risk_score, confidence, status, timestamp, log_event_id, rule_triggered) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
        [
            (
                "Brute Force Attack" if i % 3 else "SQL Injection",
                "HIGH" if i % 3 else "CRITICAL",
                f"detection {i}",
                f"203.0.{i % 200}.{i % 250}",
                40 + i % 50,
                90,
                f"2026-07-{20 + i % 9:02d} {10 + (i // 3600) % 12:02d}:{i % 60:02d}:{(i * 3) % 60:02d}",
                i + 1,
                "brute_force" if i % 3 else "sql_injection",
            )
            for i in range(n_alerts)
        ],
    )
    conn.commit()
    conn.close()


def main():
    n_events = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    n_alerts = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    db_path = os.environ.get("PERF_DB", "perf.db")
    seed(db_path, n_events, n_alerts)

    from backend.app.main import app
    from backend.app.database import get_db, SessionLocal
    from backend.app.api.auth import get_current_user
    from backend.app.models import User

    # Authenticate as the seeded user without hashing a password.
    test_db = SessionLocal()

    def override_auth():
        return test_db.query(User).filter(User.email == "perf@example.com").first()

    app.dependency_overrides[get_current_user] = override_auth
    client = TestClient(app)

    endpoints = [
        ("GET /api/threats (unbounded)", lambda: client.get("/api/threats")),
        ("GET /api/threats/stats", lambda: client.get("/api/threats/stats")),
        ("GET /api/dashboard/stats", lambda: client.get("/api/dashboard/stats")),
        ("POST /api/assistant/query", lambda: client.post("/api/assistant/query", json={"message": "What threats were detected?"})),
        ("GET /api/reports/pdf", lambda: client.get("/api/reports/pdf")),
        ("GET /api/reports/alerts.csv", lambda: client.get("/api/reports/alerts.csv")),
    ]
    print(f"\nDataset: {n_events} events, {n_alerts} alerts\n")
    for name, fn in endpoints:
        start = time.perf_counter()
        resp = fn()
        elapsed = time.perf_counter() - start
        size = len(resp.content) if resp.content else 0
        print(f"{name:35s} -> {elapsed * 1000:8.1f} ms   status={resp.status_code}  bytes={size:,}")


if __name__ == "__main__":
    main()
