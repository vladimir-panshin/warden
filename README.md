# Warden

**Session-based authentication service in Go** — TOTP 2FA, recovery codes, session management, and brute-force protection.

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Warden is an authentication backend — registration, login, two-factor authentication, and session lifecycle, and deliberately nothing else. The goal is a small, readable core that's easy to build on.

---

## Getting started

### With Docker (recommended)

```bash
cp .env.example .env
docker compose up --build
```

This starts PostgreSQL, Redis, and the service. The schema is applied automatically on first run. The API is then available at `http://localhost:8080`.

### Locally

Requires Go 1.26+, a running PostgreSQL, and Redis.

```bash
cp .env.example .env
psql "$DATABASE_URL" -f schema.sql
go run ./cmd/server
```

---

## Configuration

All configuration is via environment variables.

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis address (`host:port`) |
| `SERVER_PORT` | HTTP port (default `8080`) |
| `TRUSTED_PROXIES` | Comma-separated CIDRs of trusted reverse proxies. Empty = trust direct connections only. |

---

## API

Base path: `/api/v1`. Sessions are carried in an `HttpOnly` cookie (`session_id`); a `Bearer` token is also accepted.

### Authentication (public)

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/register` | Create an account, start a session |
| `POST` | `/auth/login` | Log in; returns `{requires_2fa:true}` if 2FA is enabled |
| `POST` | `/auth/2fa` | Complete login with a TOTP code |
| `POST` | `/auth/2fa/recovery` | Complete login with a recovery code |
| `POST` | `/auth/logout` | End the current session |

### Account (authenticated)

| Method | Path | Description |
|---|---|---|
| `GET` | `/account/me` | Current account |
| `PATCH` | `/account/me/email` | Change email |
| `PATCH` | `/account/me/password` | Change password |
| `DELETE` | `/account/me` | Delete account |
| `POST` | `/account/me/2fa/setup` | Begin 2FA setup (returns secret + QR) |
| `POST` | `/account/me/2fa/confirm` | Confirm 2FA, receive recovery codes |
| `DELETE` | `/account/me/2fa` | Disable 2FA |
| `GET` | `/account/me/sessions` | List active sessions |
| `DELETE` | `/account/me/sessions` | Revoke all other sessions |
| `DELETE` | `/account/me/sessions/:id` | Revoke a specific session |
