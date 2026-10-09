# Database and Gemini setup

The FastAPI backend owns authentication, log parsing, detections, Gemini calls, and SQLAlchemy access. Supabase supplies a hosted PostgreSQL database. The browser must never receive the database password or Gemini API key.

## 1. Create the free accounts

1. Create a Supabase project at <https://supabase.com/dashboard>. Save its database password.
2. Open the project's **Connect** panel and copy the **Session pooler** connection URI (port 5432). This mode supports a long-running SQLAlchemy application over IPv4. Use the project's actual region and project reference.
3. Create a free-tier Gemini API key at <https://aistudio.google.com/app/apikey>. Choose a free-tier project; the supported default model here is `gemini-3.1-flash-lite`. Check the quota shown in AI Studio because limits vary by account, model, and region.

Supabase Free currently includes 500 MB of database storage. Free projects may pause after low activity, and exceeding storage can make the database read-only. Gemini Free usage may be used to improve Google's products. Review those terms before sending sensitive operational data.

## 2. Install dependencies and set backend variables

From the repository root in PowerShell:

```powershell
venv\Scripts\python.exe -m pip install -r backend\requirements.txt
$env:DATABASE_URL = 'postgresql+psycopg://postgres.PROJECT_REF:URL_ENCODED_PASSWORD@aws-0-REGION.pooler.supabase.com:5432/postgres'
$env:GEMINI_API_KEY = 'YOUR_GOOGLE_AI_STUDIO_KEY'
$env:GEMINI_MODEL = 'gemini-3.1-flash-lite'
$env:SECRET_KEY = 'A_LONG_RANDOM_VALUE'
$env:ENV = 'production'
$env:DB_SSLMODE = 'verify-full'
$env:DB_SSLROOTCERT = 'C:/path/to/supabase-ca.crt'
```

Copy the actual URI from Supabase; the example hostname is only a placeholder. If the password has special characters, URL-encode it. Download your project's CA certificate from Supabase **Database Settings > SSL Configuration** and set `DB_SSLROOTCERT` to its path. `verify-full` checks the certificate and database hostname; production startup rejects weaker PostgreSQL SSL modes. An explicit `sslmode` in `DATABASE_URL` takes precedence over `DB_SSLMODE`, so remove `sslmode=require` from the URI if present. Generate a signing key with `venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(64))"`. Do not put either secret in `frontend/` or a `VITE_` variable. Environment variables set in PowerShell last for that terminal session; configure them in your deployment host too.

## 3. Copy existing SQLite data (optional)

If you want your existing local accounts and logs, stop the backend before copying. With `DATABASE_URL` pointing to a **new, empty** Supabase database:

```powershell
venv\Scripts\python.exe scripts\migrate_sqlite_to_supabase.py securesight.db
```

The script creates the tables, refuses to copy into a database with existing rows, copies tables in foreign-key order, and advances ID sequences. It reads the SQLite source without changing or deleting it. If you do not need the old local data, skip this step; backend startup creates empty tables.

## 4. Start and verify

```powershell
venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Start the frontend with `npm run dev` inside `frontend/`. Register or log in, upload a sample log, then ask the assistant for a threat summary. A `503` response means Gemini is not configured, its quota is reached, or the service is unavailable. Verify Supabase rows in the Table Editor.

SQLite remains the local default when `DATABASE_URL` is unset. Database files contain accounts, logs, alerts, and conversations and should not be committed. On startup, the backend adds recovery-code and session-version columns to existing users. Existing users must sign in and save a new recovery code from Profile; previously issued login tokens require a new sign-in after this upgrade. A user who cannot sign in and has no recovery code needs administrator-assisted account recovery.
