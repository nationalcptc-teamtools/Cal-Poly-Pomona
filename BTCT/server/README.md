# BTCT Collab Server

Auth + Yjs websocket server for Been There, Conquered That.

## Run

```bash
cd server
bun install
AUTH_SECRET="$(openssl rand -hex 32)" bun run start
```

This server uses Bun's built-in `bun:sqlite`, so it requires **Bun** to run (not stock Node). Defaults: listens on `127.0.0.1:1234`, allows CORS from `http://127.0.0.1:5173`.

## Environment

| Variable          | Default                    | Notes                                  |
| ----------------- | -------------------------- | -------------------------------------- |
| `PORT`            | `1234`                     |                                        |
| `HOST`            | `127.0.0.1`                |                                        |
| `ALLOWED_ORIGIN`  | `http://127.0.0.1:5173`    | Vite dev server origin                 |
| `AUTH_SECRET`     | dev fallback (warns)       | **Set in production.** HMAC token key. |
| `DB_PATH`         | `./data.sqlite`            | SQLite file for accounts               |

## Endpoints

- `POST /api/register` `{ username, password }` → `{ token, user }`
- `POST /api/login`    `{ username, password }` → `{ token, user }`
- `GET  /api/me`       (Bearer token)            → `{ user }`
- `WS   /yjs/<room>?token=<jwt>`                 → Yjs sync

Passwords are hashed with PBKDF2-SHA256 (210k iterations, 16-byte salt, 32-byte key). Tokens are HMAC-SHA256 signed and expire after 7 days.
