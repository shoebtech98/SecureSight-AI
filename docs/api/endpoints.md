# SecureSight AI API

All application routes below require a Bearer JWT unless marked public. The frontend sends the token in the `Authorization` header.

## Authentication

- `POST /api/auth/register` — public; creates a user and returns a one-time recovery code to save securely.
- `POST /api/auth/login` — public; returns an access token.
- `POST /api/auth/refresh` — returns a replacement access token.
- `POST /api/auth/forgot-password` — public; returns the same recovery instructions for every address.
- `POST /api/auth/reset-password` — public; accepts `email`, `recovery_code`, and `new_password`; consumes the code and revokes older sessions.
- `POST /api/auth/recovery-code` — requires a session and current password; returns a replacement code once and a fresh access token.
- `GET /api/auth/me` — returns the current user.
- `PUT /api/auth/me` — updates profile and credentials; sensitive changes require the current password, revoke older sessions, and return a fresh token.

## Logs and events

- `POST /api/logs/upload` — validates and ingests `.log`, `.txt`, `.csv`, or `.json`.
- `GET /api/logs/files` — lists the current user’s uploaded files.
- `DELETE /api/logs/files/{file_id}` — deletes a file and its associated events/alerts.
- `GET /api/logs/events` — searches and filters events with `level`, `service`, `ip_address`, `classification`, `search`, `skip`, and `limit`.

## Threats

- `GET /api/threats` — paginated alerts with `status`, `severity`, `skip`, and `limit`.
  - Includes an `X-Total-Count` response header containing the filtered total.
- `PUT /api/threats/{alert_id}` — changes an alert to `active`, `resolved`, or `false_positive`.
- `GET /api/threats/stats` — aggregate status and severity counts.

## Dashboard

- `GET /api/dashboard/stats` — aggregate events, threats, timelines, distributions, top IPs, and recent alerts.

## Assistant

- `POST /api/assistant/query` — sends bounded, user-scoped SIEM aggregates to Gemini and persists the answer; returns 503 if Gemini is unavailable or unconfigured.
- `GET /api/assistant/conversations` — lists the user’s conversations.
- `GET /api/assistant/conversations/latest` — restores the most recently updated conversation and its messages.
- `DELETE /api/assistant/conversations` — clears the user’s chat history.

## Reports

- `GET /api/reports/pdf` — generates a security-posture PDF from database aggregates.
- `GET /api/reports/alerts.csv` — exports alerts as CSV.

## Health

- `GET /` — public backend health check.
