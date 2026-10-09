# SecureSight AI backend

The backend is a FastAPI application packaged as `backend.app`.

## Layout

- `app/main.py` — FastAPI application, CORS, and router registration.
- `app/api/` — HTTP routes for auth, logs, threats, dashboard, assistant, and reports.
- `app/core/` — password/JWT security and request rate limiting.
- `app/database/` — SQLAlchemy base, session handling, and SQLite/PostgreSQL schema/index setup.
- `app/services/gemini.py` — server-side Gemini request with bounded SIEM context.
- `app/models/` — ORM entities.
- `app/schemas/` — Pydantic request/response contracts.
- `app/services/` — event normalization.
- `app/detection/` — signature detection, correlation, and risk scoring.
- `app/parsers/` — log-format parsing and timestamp handling.
- `tests/` — unittest audit suite and performance harness.

## Run

From the repository root:

```powershell
venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

## Test

From the repository root, using an isolated database:

```powershell
$env:DATABASE_URL="sqlite:///./test_run.db"
venv\Scripts\python.exe -W error::DeprecationWarning -m unittest backend.tests.test_audit_suite backend.tests.test_security_regressions
```

The repository-level `scripts/verify.py` performs the same backend check and then runs frontend lint and build.

Registration issues a one-time recovery code, stored as a password hash and shown only in the response. Signed-in users can replace it from Profile after entering their password. A successful password reset consumes the code and revokes existing access tokens. Startup adds the recovery-code and session-version columns to older databases. Existing accounts must sign in and generate a code before they can use self-service recovery.
