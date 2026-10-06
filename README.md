# SecureSight AI — Conversational SIEM Assistant

SecureSight AI is a final-year B.Tech project demonstrating an end-to-end Security Information and Event Management workflow:

Login → Upload Log → Parse → Normalize → Store → Detect → Alert → Monitor → Explore → Investigate → Report.

The conversational assistant uses Gemini with bounded, user-scoped SIEM aggregates. Threat detection itself remains rule-based. SQLite is available for local development; Supabase PostgreSQL is supported for hosted data.

## Repository layout

- `frontend/` — React/Vite user interface.
- `backend/` — FastAPI application and automated tests.
  - `backend/app/` — API, core security, database, models, schemas, services, detection, and parsers.
  - `backend/tests/` — unittest audit suite and performance harness.
  - `backend/requirements.txt` — backend dependencies.
  - `backend/README.md` — backend-specific documentation.
- `data/samples/` — demonstration SSH and Nginx logs.
- `database/` — SQLite and Supabase PostgreSQL documentation.
- `docs/` — architecture, API, and historical project documentation.
- `scripts/` — repository verification script.
- `.env.example` — local configuration template.

## Prerequisites

- Python 3.13
- Node.js 22
- `npm`

## Backend setup

From the repository root:

```powershell
python -m venv venv
venv\Scripts\pip install -r backend\requirements.txt
```

Set `GEMINI_API_KEY`, `GEMINI_MODEL`, `DATABASE_URL`, and `SECRET_KEY` in the backend process environment or a project-root `.env` file. See [database/README.md](database/README.md) for the Supabase and Gemini setup sequence. Gemini calls need internet access from the backend server.

Run the backend:

```powershell
venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

## Frontend setup

From `frontend/`:

```powershell
npm install
npm run dev
```

The Vite development server runs on `http://127.0.0.1:5173` and proxies `/api/*` to `http://127.0.0.1:8000`.

## Verification

Run the complete repository check from the repository root:

```powershell
python scripts\verify.py
```

This runs:

1. Backend unittests against an isolated temporary database.
2. Frontend lint.
3. Frontend production build.

Backend tests can also be run directly:

```powershell
$env:DATABASE_URL="sqlite:///./test_run.db"
venv\Scripts\python.exe -W error::DeprecationWarning -m unittest backend.tests.test_audit_suite
```

## Demonstration data

Upload either file from `data/samples/` through **Upload Logs**:

- `ssh_auth.log`
- `nginx_access.log`

Together they produce authentication failures, a brute-force correlation, SQL injection, XSS, directory traversal, and directory-reconnaissance alerts.

## Documentation

- `docs/architecture/overview.md`
- `docs/api/endpoints.md`
- `backend/README.md`
- `frontend/README.md`
- `database/README.md`
- `data/README.md`
- `docs/project/audit-report.md` — historical audit artifact; some paths predate this reorganization.
