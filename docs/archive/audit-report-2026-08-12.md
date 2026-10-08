# SecureSight AI — End-to-End Technical Audit Report

> Historical snapshot from 2026-08-12. Several findings and file paths below are
> outdated. Use the current root README, architecture notes, and API documentation
> for the present project structure and behavior.

Date: 2026-08-12

## Scope

Full-stack audit of SecureSight AI (FastAPI + SQLite backend, React/Vite frontend): authentication, log ingestion and parsing (9 formats), normalization, threat detection and correlation, Event Explorer, Threat Monitor, Dashboard, conversational AI assistant, and report generation/export. Every component was inspected and exercised against real data.

## Verification Environment

- Backend: uvicorn on `127.0.0.1:8000`; frontend: Vite dev server on `127.0.0.1:5173` with `/api` proxied to the backend.
- `python -m unittest backend/tests/test_audit_suite` — **13 tests, all pass** (isolated DB).
- Frontend `npm run build` — passes; `npm run lint` — **0 warnings, 0 errors** (was 24 warnings).
- Live end-to-end run in the browser preview: register → login → upload `ssh_auth.log` + `nginx_access.log` → Event Explorer → Threat Monitor → Dashboard → AI Assistant → Reports (PDF/CSV) → triage (resolve alert).
- API-level E2E (16 steps) via the running server: register, login, invalid credentials (401), missing token (401), malformed token (401), both uploads (200), event retrieval with `source_ip`, paginated threats, threat stats, dashboard stats, assistant queries, PDF export, CSV export, email-change token re-issue.

---

## Working Correctly (verified)

- **Frontend ↔ Backend connectivity.** Vite proxy `/api → http://127.0.0.1:8000` is correct; every page's XHR (auth, logs, threats, dashboard, assistant, reports) returned 200 through the proxy. The `ECONNREFUSED 127.0.0.1:8000` error is simply the backend not running — no proxy/config defect exists.
- **Authentication.** Register (201), login (200), remember-me (localStorage vs sessionStorage), `/api/auth/me`, `/api/auth/refresh`, invalid credentials (401), missing/malformed tokens (401), forgot/reset password flow, profile update. Password policy now consistent (min 8 chars) across register, reset, and profile.
- **Log ingestion & parsing.** Uploads validate extension (`.log/.txt/.csv/.json`), reject empty files (400) and files > 25 MB (413). All 9 parser formats verified: Apache/Nginx, SSH auth, Windows Event, syslog, firewall (iptables/UFW), Snort fast log, Suricata JSON, Zeek TSV, and CSV. Field extraction verified (timestamp, source/dest IP, username, port, protocol, service, event type, severity, action/status, message).
- **Source IP field flow.** `parser → normalizer → LogEvent.source_ip → API → Event Explorer` verified end-to-end. `source_ip` and `ip_address` are both populated; the API returns `source_ip or ip_address`; the frontend displays `source_ip || ip_address || src_ip`. No field is lost or renamed.
- **Threat detection.** Verified against real suspicious samples: Brute Force (5 failed logins from `192.168.2.110`), SQL Injection (`UNION SELECT`), XSS (`<script>` payload), Directory Traversal (`../../etc/passwd`), Directory Reconnaissance (17× 404 probes from `192.168.1.99`), Authentication Failures, Port Scan (6 distinct destination ports in 2 minutes), Privilege Escalation indicators, plus malware/command-injection signatures in the detection test matrix. Detection → severity → risk score → alert → DB → Threat Monitor → Dashboard all verified.
- **Event Explorer.** Displays real DB events (not mock): timestamp, level, service, source IP, message, classification. Search, filters (level/service/classification/IP), pagination, detail drawer, and empty/error states work. IP filter verified via API.
- **Threat Monitor.** Loads quickly, shows real alerts with severity/risk/confidence/status, per-alert triage (resolve / false positive) updates stats live (verified: active 12→11, resolved 0→1), raw-evidence inspection, status tabs, severity filter, and **pagination**.
- **Dashboard.** All KPIs and charts computed from the database: total events, threats, active incidents, files, critical alerts, high-risk IPs, brute-force/SQLi/malware/auth-failure counters, events-over-time, threat-type distribution, top suspicious IPs, recent alerts. Empty state renders when no files exist.
- **AI Assistant.** Database-backed and context-aware. Verified answers use the *actual uploaded data*: it lists the uploaded files by name with status/size, reports the correct event/threat counts, and identifies `192.168.2.110` (6 alerts) as the top attacker IP — matching the brute-force source in the uploaded `ssh_auth.log`. No hallucinated content; responses are deterministic retrievals from SQL aggregates.
- **Reports.** PDF contains real counts (events, threats, active, files, max risk), severity distribution, top attacker IPs, and a 25-row incident registry; CSV exports all alerts. No placeholders or example data.
- **Triage & lifecycle.** Deleting a log file cascades events and alerts (ORM cascade).

---

## Errors Found → Root Cause → Fix → Verification

### 1. Threat Monitor (and Dashboard/Assistant/Reports) unacceptably slow
→ `GET /api/threats` returned **every** alert for the user with no limit. The shared database contains **500,051 events / 104,687 alerts** (from a 39.8 MB CSV uploaded by a user), so the endpoint materialized ~104k rows into a 16.6 MB JSON payload (~2 s + rendering).
→ No pagination/bounds on the threats endpoint; the frontend rendered the entire list.
→ Added `skip`/`limit` (default 200, cap 500) to `GET /api/threats` and pagination UI in Threat Monitor; consolidated `/api/threats/stats` from 7 count queries to 2 `GROUP BY` queries.
→ **Measured (100k events / 20k alerts): 2062 ms / 16.6 MB → 94 ms / 166 KB (22× faster, 100× smaller payload).**

### 2. AI Assistant took ~12 seconds per query
→ `query_assistant` loaded **all** of the user's events and alerts into Python objects (`_user_events(...).all()`, `_user_alerts(...).all()`) just to count and summarize them.
→ Replaced full-table materialization with SQL aggregates: counts, `GROUP BY` status/severity/threat-type, top-10 source IPs, highest-risk alert, and 15 recent alerts only.
→ **Measured: 12,044 ms → 211 ms (57× faster).** Conversation persistence and the response JSON contract (`matching_alerts`, `source_ips`, `highest_risk_alert`) are unchanged.

### 3. Report PDF generation ~2.8 s and memory-heavy
→ PDF endpoint loaded **all** events (just to count them) and **all** alerts (104k) into memory.
→ Counts and distributions now come from SQL aggregates; only the 25 newest alerts are materialized for the incident table; CSV export streams with `yield_per`.
→ **Measured: 2,776 ms → 211 ms (13× faster).** PDF contents unchanged.

### 4. Massive false positives: 104,661 CRITICAL "Privilege Escalation" alerts from one file
→ The `privilege_escalation` rule contained the bare substring `"sudo"` (plus `"administrator"`). The uploaded CSV has a `username` column whose values include `sudo`/`su`, so **every row matched** → 104,661 CRITICAL alerts. The `command_injection` rule was similarly broad (`&&`, `||`, `wget`, `curl` match routine traffic).
→ Refined indicators to unambiguous signatures: privilege escalation now requires `session opened for user root`, `root login`, `privilege granted`, `privileges assigned`; command injection requires explicit payloads (`;cat /etc/passwd`, `;whoami`, `powershell -enc`, `/bin/sh -c`, …). Privilege-escalation severity lowered CRITICAL → HIGH (non-confirmed indicator).
→ Regression tests added: a user named `sudo`, `q=hello&&world`, `curl: failed to connect`, and `administrator logged in` all produce **no** alerts; a genuine root-session escalation still fires. **Existing 104k false alerts in the DB are historical data** (see Remaining Issues).

### 5. CSV files were not actually parsed as CSV
→ `.csv` was an accepted extension and the upload page claimed CSV support, but the parser treated each line as generic text (the header row was stored as an event; columns like `source_ip`, `username`, `status` were lost).
→ Added content-detected CSV parsing: recognized header row (e.g. `timestamp,source_ip,city,username,service,attempts,status,port,protocol`) is skipped, and rows are mapped to the common event shape (timestamp, source/dest IP, username, service, port, protocol, action/status, level).
→ Verified by unit test and on the real 40 MB CSV shape (no more header-as-event, fields extracted).

### 6. Event Explorer classification filters returned nothing
→ Dropdown values (`sql_injection_attempt`, `ssh_failed`, `cross-site_scripting_(xss)_attempt`, …) did not match the stored `classification` values (rule names like `sql_injection`, `failed_login`, `xss`).
→ Updated the dropdown to the actual stored values (`clean`, `failed_login`, `repeated_failed_login`, `sql_injection`, `xss`, `directory_traversal`, `command_injection`, `malware_indicator`, `privilege_escalation`, `port_scan`, `suspicious_authentication`).

### 7. Changing your email logged you out
→ The JWT carries the email in `sub`; `PUT /api/auth/me` changed the email, so the next request looked up the old email → 401 → forced logout.
→ On email change the backend re-issues a fresh token and returns it (`access_token` in the profile-update response); the Profile page persists it. Verified: new token works immediately after the change.

### 8. "Directory Reconnaissance" alerts mislabeled as `PORT_SCAN`
→ The 404-recon correlation reused the `port_scan` rule name, so Event Explorer showed recon events classified `PORT_SCAN`.
→ Split into its own `directory_reconnaissance` rule/threat-type with its own risk score. (Applies to newly ingested data.)

### 9. Timestamps silently rewritten to "now" on parse failure
→ `parse_datetime` returned `datetime.utcnow()` on any failure, so malformed/unrecognized timestamps were stored as the current time — corrupting timelines and correlation windows.
→ Parse failures now yield `None` (displayed as "Unavailable"; excluded from timeline and correlation). Verified by unit tests.

### 10. Internal errors leaked to users
→ Upload/register paths returned `str(e)` / `str(db_err)` to clients.
→ Exceptions are logged server-side with the real detail; clients receive a generic, actionable message. Log files record a sanitized failure reason.

### 11. Directory-recon / Windows-event parsing over-triggered
→ The Windows parser triggered on any line containing bare `4624`/`4625`/`4672` substrings (e.g. a port number), and the recon 404 correlation threshold was fine but the rule naming was wrong (see #8).
→ Windows detection now requires an explicit `EventID`/`Event ID`/`EventCode` marker.

### 12. Notifications showed hardcoded mock alerts
→ The bell dropdown displayed static "Brute Force Attack Detected"/"SQL Injection Attempt" entries.
→ Wired to real `recent_threats` from the dashboard API; shows a clean "No recent alerts" empty state.

### 13. Frontend lint: 24 warnings; dead code
→ Removed unused imports (`Printer`, `BarChart2`, `AlertCircle`, `XCircle`, `ArrowUpRight`, `Legend`, `Bar`, `BarChart`, `Shield`, `AlertTriangle`, `Input`) and dead functions/variables (`handlePrint`, `statusBreakdown`, `strengthLabel`, unused `Icon`, unused `response`), fixed hook-dependency warnings with `useCallback`, and corrected a regex escape. **0 warnings / 0 errors now.**

### 14. Upload timeout for large files
→ The default 10 s axios timeout could abort large uploads while the backend was still parsing.
→ Upload requests now use a 10-minute timeout; backend inserts events in bulk (`bulk_save_objects`) instead of per-row ORM adds.

---

## Performance Improvements (measured, 100k events / 20k alerts)

| Endpoint | Before | After | Δ |
|---|---|---|---|
| GET /api/threats | 2,062 ms / 16.6 MB | 94 ms / 166 KB | ~22× faster, ~100× smaller |
| GET /api/threats/stats | 81 ms | 64 ms | consolidated 7→2 queries |
| GET /api/dashboard/stats | 465 ms | 383 ms | consolidated ~15→10 queries |
| POST /api/assistant/query | 12,044 ms | 211 ms | ~57× faster |
| GET /api/reports/pdf | 2,776 ms | 211 ms | ~13× faster |
| GET /api/reports/alerts.csv | 559 ms | 433 ms | streamed (`yield_per`) |

The 500k-event dataset in `securesight.db` is now served comfortably by every endpoint.

---

## Corrections Made — Files Changed

**Backend**
- `backend/utils/log_parser.py` — real CSV parsing, refined Windows trigger, honest timestamps, simpler return type.
- `backend/services/detection_engine.py` — narrowed privilege-escalation and command-injection indicators.
- `backend/services/correlation_engine.py` — separate `directory_reconnaissance` rule.
- `backend/services/risk_scoring.py` — privilege-escalation HIGH; recon scoring.
- `backend/routes/threats.py` — pagination + consolidated stats.
- `backend/routes/dashboard.py` — consolidated aggregates.
- `backend/routes/assistant.py` — SQL aggregates only; removed dead duplicate block and unused imports.
- `backend/routes/reports.py` — counts/aggregates instead of full-table loads; streaming CSV.
- `backend/routes/logs.py` — bulk inserts, sanitized errors, logging.
- `backend/routes/auth.py` — email-change token re-issue; sanitized errors.
- `backend/schemas.py` — password policy (min 8), `UserUpdateResponse` with optional token.
- `backend/main.py` — startup warning when `SECRET_KEY` unset.
- `backend/tests/test_audit_suite.py` — extended to 13 tests (CSV, false-positive regressions, correlation, pagination, email-change).
- `backend/tests/perf_benchmark.py` — new repeatable performance harness.

**Frontend**
- `EventExplorer.jsx` — correct classification filter values; `useCallback` fetch.
- `ThreatMonitor.jsx` — pagination; filter→page-1 reset.
- `Reports.jsx` — removed dead code; streamlined imports.
- `AIAssistant.jsx`, `Register.jsx`, `ForgotPassword.jsx`, `UploadLogs.jsx`, `Profile.jsx`, `DashboardLayout.jsx` — lint cleanup, `.json` support + upload timeout, token refresh on email change, real notification data, aligned password policy (8 chars).

---

## Follow-up Fixes (2026-08-12, after initial audit)

### 15. Deleting large log files failed / hung in Upload Logs
→ `DELETE /api/logs/files/{id}` used the ORM cascade (`cascade="all, delete-orphan"`), which loads every related event and alert into memory and deletes row-by-row. A 100k-event file took **36 s** — over the frontend's 10 s axios timeout, so the UI showed "Failed to delete log file" even though the backend eventually finished. The 500k-event CSV in the DB would take minutes.
→ Rewrote the delete to set-based bulk deletes in dependency order (`threat_alerts → log_events → log_files`), no ORM cascade.
→ **Measured: 36 s → 0.9 s for 100k events; 121 ms live for a small file.** Verified live: upload → delete → event count returns to 0.

### 16. Sign-up accepted weak passwords
→ The registration page showed a strength meter but only enforced a minimum length; the backend accepted any password.
→ Enforced a consistent policy — **≥ 8 chars with uppercase + lowercase + digit + special character** — on both the backend (Pydantic validators on register, reset, and profile-update) and the frontend (blocking submit with a specific error on Register, Forgot Password, and Profile pages).
→ Verified live: `weakpass123` → 422; test suite extended (weak register, weak policy register, weak reset all rejected).

### 17. UI polish round (2026-08-12): progress bar, activity timeline, working top-nav search
- **Upload progress bar** — `UploadLogs.jsx` now shows a real upload/parse progress bar (`onUploadProgress`) instead of an indeterminate spinner, so large files no longer look frozen.
- **Dashboard activity timeline** — the timeline panel is now a combined `ComposedChart` (events bar + threats line, Recharts) merged client-side from `events_over_time` and `threat_timeline`. Also fixed a data-alignment bug: threat alerts were timestamped at *generation* time (today) while events kept their source-log date, so the two series landed on different days. `dashboard.py` now derives the threat-timeline date from the triggering event's timestamp — verified via TestClient: both series align on the source event date.
- **Working top-nav search** — the header search box (previously a dead stub) now navigates to `/explorer?q=<query>`; `EventExplorer.jsx` reads the `q` param and applies it as a filter. Fixed a race where the deep-link-triggered filtered fetch could be overwritten by the initial unfiltered fetch (stale-response guard via a request sequence ref). Verified live: `?q=192.168.1.55` → 1 row (SQLi event); nav-search submit → same filtered result.
- **Dark mode theme toggle** — new `ThemeToggle.jsx` (Sun/Moon button) in the top nav and on all auth pages (Login/Register/Forgot Password). The whole app flips via a runtime CSS-variable remap of the Tailwind palette in `index.css` (`.dark` scope redefines `--color-white`, the slate scale, and `bg-main/bg-sec/bg-card`), so no per-component `dark:` classes were needed. Semantics that must not flip are pinned explicitly (white-on-primary text, `bg-slate-700` detail panels/scrims). Charts are theme-aware via `--chart-grid`/`--chart-tick` CSS vars. Persisted in `localStorage('ss-theme')` and applied before first paint by an inline script in `index.html` (no flash; respects system preference as the default). Also fixed the browser tab title (was `frontend`).
- **Verification:** lint 0 warnings / 0 errors, production build passes.

### 18. Dashboard: threat-severity donut + Top Attacking IPs (2026-08-12)
- **Severity donut** — the API already computed alert-severity counts internally but never exposed them (`severity_distribution` was *event-level* and unused by the frontend). Added `alert_severity_distribution` to `GET /api/dashboard/stats` (stable CRITICAL→HIGH→MEDIUM→LOW→INFO order, empty when no alerts) and built a donut chart from it with a center total + severity legend. Verified live with real data: CRITICAL 1 / HIGH 3 / MEDIUM 1 / LOW 7, center "12 Alerts" — matches the API exactly.
- **Top Attacking IPs** — the card existed (`stats.top_ips`) but was plain; upgraded it with rank medals and proportional activity bars (100 % / 33 % / 17 % of the top IP's count). Verified live: `192.168.2.110` (6 alerts) → `192.168.1.66` (1).
- **Found & fixed a pre-existing chart bug:** **both** Recharts pie charts (the old Threat Types pie and the new donut) rendered **zero sectors** — the `recharts-shape` groups were empty. Root cause: Recharts 3.9.2's pie *entry animation* never completes under React 19 `<StrictMode>` double-mounting, so the sector paths are never drawn (silently — no console errors). The Threat Types pie had been showing legend-only, empty, all along. Fix: `isAnimationActive={false}` on both `<Pie>`s. Verified: Threat Types 6 sectors, Severity donut 4 sectors, each with the correct fill colors.
- **Verification:** lint 0 warnings / 0 errors, production build passes; full backend suite 13/13 via `python -m unittest tests.test_audit_suite` (note: the venv does not include pytest — the suite is `unittest`-based).

---

## Remaining Issues / Not Verified

- **~~The historical false-positive dataset~~ / ~~220 MB bloat — RESOLVED 2026-09-08.~~** `VACUUM` has now been run on `securesight.db` and `securesight_preview.db`: 210 MB → 4.5 MB and 0.3 MB respectively (~415 MB reclaimed). `PRAGMA integrity_check` = ok on both. **Deprecated `datetime.utcnow()` usages were also removed** (models, security, reports, log_parser, tests) in favor of a shared `backend/utils/timeutil.utc_now()` helper that returns the same naive-UTC value — zero DeprecationWarnings now, storage format unchanged, 16/16 tests pass.
- **No external LLM integration.** The AI Assistant is deterministic database retrieval (by design). It does not call an external model, does not retain multi-turn conversation memory beyond chat persistence, and the frontend keeps a local fallback answerer used only when the API is unreachable.
- **JWT/logout semantics:** logout is client-side; issued JWTs remain valid until expiry. No refresh-token rotation or revocation; `/api/auth/refresh` simply re-issues. No rate limiting. `SECRET_KEY` must be set in production (startup warning added).
- **Upload is synchronous.** Parsing happens inside the request; a background job with progress would be the next step for very large files. A 25 MB cap applies.
- **Duplicate alerts across re-uploads** of the same file are not deduplicated.
- **Dashboard `severity_distribution`** key is event-level counts (unused by the frontend); naming could be clarified to `level_distribution`.
- **Timezone handling:** timestamps are parsed as naive UTC; syslog year defaults to the current year. Offsets are not converted.
- **Port-scan correlation** requires destination-port parsing (firewall/IDS/Zeek formats); it cannot fire from Apache/SSH logs, which is expected but worth knowing.
- **Notification bell** only loads on layout mount/route change (no polling) — acceptable for this dataset.
- No `requirements.txt` exists for the backend (the project venv has the deps installed).
- Production concerns from the prior audit remain: no rate limiting, no request correlation IDs, no centralized exception middleware, bundle > 500 kB (route-level code splitting would help).

---

## End-to-End Verification

**Login → Upload → Parse → Normalize → Store → Detect → Alert → Monitor → AI Investigation → Report Export: ✅ VERIFIED WORKING END-TO-END** on the live system, using the real sample logs (`ssh_auth.log`, `nginx_access.log`) and the shared database — through both the API and the browser UI. Every stage produced and displayed real data: 32 parsed events, 12 alerts (brute force, SQLi, XSS, traversal, recon, auth failures), correct source-IP extraction, live dashboard KPIs, database-backed assistant answers, and PDF/CSV exports with correct statistics.

Not claimed: 100% of every conceivable log format, external-LLM quality answers, or production-hardening (rate limits, token revocation, background ingestion) — those require additional configuration/data and are listed above.
