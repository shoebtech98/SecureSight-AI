# SecureSight AI architecture

## Request flow

```text
React/Vite frontend
→ Vite /api proxy
→ FastAPI backend
→ log upload and parsing
→ event normalization
→ signature detection and correlation with nearby events from the user's earlier files
→ SQLite (local) or Supabase PostgreSQL storage
→ dashboard, Event Explorer, and Threat Monitor
→ Gemini security assistant with database aggregates
→ PDF/CSV reports
```

## Backend modules

- `backend/app/main.py`
  - Creates the FastAPI application.
  - Configures CORS for the local frontend.
  - Registers API routers.
- `backend/app/api/`
  - `auth.py`: registration, login, session/profile management, and password recovery.
  - `logs.py`: upload, validation, parsing/normalization orchestration, event search, and file deletion.
  - `threats.py`: paginated alerts, triage updates, and aggregate stats.
  - `dashboard.py`: aggregate KPIs, timelines, distributions, and recent alerts.
  - `assistant.py`: user-scoped database aggregates sent to Gemini for a grounded answer.
  - `reports.py`: PDF and CSV exports.
- `backend/app/core/`
  - Password hashing, JWT creation/validation, and rate limiting.
- `backend/app/database/`
  - SQLAlchemy models’ base class, sessions, schema creation, and indexes.
- `backend/app/models/`
  - Users, log files, log events, threat alerts, conversations, and chat messages.
- `backend/app/schemas/`
  - Pydantic request/response contracts.
- `backend/app/services/`
  - Normalization into a common event shape and server-side Gemini client.
- `backend/app/detection/`
  - Signature rules, multi-event correlation, and severity/risk scoring.
- `backend/app/parsers/`
  - Format-specific log parsing and UTC timestamp handling.

## Data relationships

- A user owns log files.
- A log file owns parsed log events.
- A threat alert links to the event that triggered it.
- Cross-file alerts also track contributing earlier files so deleting a source removes dependent alerts.
- A user owns assistant conversations.
- A conversation owns user and assistant messages.

## Assistant behavior

The assistant calls Gemini through the backend. It:

1. Reads the current user’s uploaded files.
2. Uses SQL counts and grouped aggregates for events, alerts, severities, threat types, source IPs, and highest-risk alerts.
3. Sends the question and a bounded summary to Gemini; raw log messages and alert evidence are excluded.
4. Includes a bounded recent conversation history for follow-up questions.
5. Persists both the question and generated answer as a conversation, which the UI restores after reload.
