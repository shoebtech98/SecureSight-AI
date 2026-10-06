# SecureSight AI frontend

The frontend is a React + Vite single-page application.

## Layout

- `src/main.jsx` — application entry point.
- `src/App.jsx` — public and protected routes.
- `src/pages/` — Login, Register, Forgot Password, Profile, Dashboard, Upload Logs, Event Explorer, Threat Monitor, AI Assistant, and Reports.
- `src/components/` — reusable form, alert, routing, and theme controls.
- `src/layouts/` — authenticated dashboard shell, navigation, search, notifications, and logout.
- `src/services/api.js` — Axios client, JWT handling, and unauthorized-session handling.
- `src/utils/datetime.js` — shared UTC timestamp formatting.
- `src/assets/` — static frontend assets.
- `public/` — static public files.

## Development

From `frontend/`:

```powershell
npm install
npm run dev
```

The development server proxies frontend `/api/*` requests to the backend at `http://127.0.0.1:8000`; see `vite.config.js`.

## Checks

From `frontend/`:

```powershell
npm run lint
npm run build
```
