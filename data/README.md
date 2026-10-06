# SecureSight AI sample data

`data/samples/` contains small demonstration logs for academic evaluation:

- `ssh_auth.log` — SSH authentication successes and failures, including a brute-force-like burst.
- `nginx_access.log` — web requests, including SQL injection, XSS, traversal, and directory-reconnaissance patterns.

These files are fixtures for manual upload through **Upload Logs** or the `/api/logs/upload` endpoint. The application does not automatically ingest them.
