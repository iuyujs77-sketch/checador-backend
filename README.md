# Checador Backend (Cloud, cookies)
- Autenticación vía cookies HttpOnly (`admin_jwt`, `emp_jwt`).
- CORS con credenciales habilitadas; configura `CORS_ORIGIN`, `COOKIE_DOMAIN`, `COOKIE_SECURE`.

## Pasos
1) Postgres: ejecutar `db/schema.sql`.
2) Backend: `cp .env.sample .env`, edita variables; `npm i && npm start`.
3) Frontend: servir `/frontend` (Netlify/Pages). Añade `window.API_BASE` si backend está en dominio distinto.
