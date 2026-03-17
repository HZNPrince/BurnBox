# 🔥 BurnBox

A self-hostable, encrypted secret sharing API built in Rust. Share passwords, API keys, and sensitive files through one-time links that self-destruct after viewing.

**The server never stores the raw decryption key.** Once a secret is viewed or expires, it is permanently deleted.

---

## Features

- 🔐 **AES-256-GCM Envelope Encryption** — each secret gets its own random key, encrypted by a master key
- 🔥 **Burn-on-read** — secrets self-destruct after the first view
- ⏰ **Time-based expiry** — auto-deleted by a background worker
- 🔑 **Password protection** — optional Argon2-hashed password gate
- 📁 **File support** — store encrypted file blobs on disk (S3-ready via trait abstraction)
- 🗄️ **Compile-time checked SQL** — all queries verified at build time via sqlx
- 📝 **Access logging** — every view attempt is recorded with outcome

## Tech Stack

| Component | Choice |
|---|---|
| Language | Rust (stable, 2021 edition) |
| HTTP Framework | Axum 0.8 |
| Database | PostgreSQL via sqlx |
| Encryption | AES-256-GCM (`aes-gcm` crate) |
| Password Hashing | Argon2id |
| Async Runtime | Tokio |
| Logging | `tracing` + `tracing-subscriber` |

---

## Quick Start

### Prerequisites
- Rust (stable)
- PostgreSQL 14+

### 1. Clone & configure

```bash
git clone https://github.com/HZNPrince/BurnBox.git
cd BurnBox
cp .env.example .env
```

Generate a master encryption key:
```bash
openssl rand -base64 32
```

Paste it as `MASTER_KEY` in `.env`.

### 2. Setup PostgreSQL

```sql
CREATE USER burnbox WITH PASSWORD 'burnbox';
CREATE DATABASE burnbox OWNER burnbox;
```

Migrations run automatically on startup.

### 3. Run

```bash
cargo run
```

```
INFO burnbox: Starting BurnBox on 0.0.0.0:8080
INFO burnbox::db: Database connected and migrations applied
INFO burnbox: Listening on 0.0.0.0:8080
```

---

## API

### `GET /health`
```bash
curl http://localhost:8080/health
```
```json
{"status": "ok", "version": "0.1.0"}
```

### `POST /secrets` — Create a secret
```bash
curl -X POST http://localhost:8080/secrets \
  -H "Content-Type: application/json" \
  -d '{"content": "super_secret_api_key", "content_type": "text"}'
```
```json
{
  "id": "f7c2db60-85dc-4767-9221-27b887727bda",
  "url": "/secrets/f7c2db60-85dc-4767-9221-27b887727bda",
  "expires_at": "2026-03-17T15:35:24Z"
}
```

**Options:**
| Field | Type | Default | Description |
|---|---|---|---|
| `content` | string | required | The secret content |
| `content_type` | string | required | `"text"` or `"file"` |
| `password` | string | null | Optional password protection (5-30 chars) |
| `burn_on_read` | bool | `true` | Delete after first view |
| `expires_in_seconds` | int | `86400` | Time until auto-expiry |

### `GET /secrets/{id}` — View a secret
```bash
curl http://localhost:8080/secrets/f7c2db60-85dc-4767-9221-27b887727bda
```
```json
{
  "content_type": "text",
  "content": "super_secret_api_key",
  "viewed_at": "2026-03-16T15:37:33Z"
}
```

**Second request → burned:**
```json
{"error": "Secrets not found"}
```

**Password-protected secret:**
```bash
curl http://localhost:8080/secrets/{id} \
  -H "X-Secret-Password: mypassword"
```

### `DELETE /secrets/{id}` — Manually revoke
```bash
curl -X DELETE http://localhost:8080/secrets/{id}
```
```json
{"status": "deleted"}
```

---

## Encryption Design

BurnBox uses **envelope encryption** — the same pattern used by AWS KMS and Google Cloud KMS.

```
┌─────────────────────────────────────────────────────────┐
│                     CREATE                              │
│                                                         │
│  Plaintext ──► AES-GCM(DEK) ──► Ciphertext             │
│                  │                                      │
│              Random DEK ──► AES-GCM(KEK) ──► Enc. DEK  │
│                                                         │
│  Stored: Ciphertext + Encrypted DEK + Nonces           │
│  Discarded: Raw DEK                                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                      READ                               │
│                                                         │
│  Enc. DEK ──► AES-GCM(KEK) ──► Raw DEK                 │
│                                    │                    │
│  Ciphertext ──► AES-GCM(DEK) ──► Plaintext              │
│                                                         │
│  After read: Row + blob deleted (if burn-on-read)       │
└─────────────────────────────────────────────────────────┘
```

- **KEK** (Key Encryption Key): Your `MASTER_KEY` env var — encrypts/decrypts DEKs
- **DEK** (Data Encryption Key): Random per-secret — encrypts/decrypts content
- The raw DEK never touches the database

---

## Project Structure

```
burnbox/
├── src/
│   ├── main.rs          # Axum router, state init, worker spawn
│   ├── config.rs        # Env config parsing
│   ├── db.rs            # PostgreSQL pool + migrations
│   ├── crypto.rs        # AES-256-GCM envelope encryption + Argon2
│   ├── storage.rs       # BlobStorage trait + local disk impl
│   ├── worker.rs        # Background expiry cleanup task
│   ├── errors.rs        # Typed error enum → HTTP responses
│   └── routes/
│       ├── mod.rs
│       ├── health.rs    # GET /health
│       └── secrets.rs   # POST/GET/DELETE /secrets
├── migrations/
│   └── 001_init.sql     # Schema: secrets + access_log tables
├── Cargo.toml
├── .env.example
└── README.md
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | — | PostgreSQL connection string |
| `MASTER_KEY` | ✅ | — | 32-byte base64-encoded AES key |
| `HOST` | ❌ | `0.0.0.0` | Server bind address |
| `PORT` | ❌ | `8080` | Server port |
| `STORAGE_PATH` | ❌ | `./data/blobs` | File blob storage directory |

---

## Roadmap

- [ ] CLI client
- [ ] Docker / docker-compose
- [ ] JIT credential generation (temp Postgres users, Redis tokens)
- [ ] Webhook on view/expiry
- [ ] S3 storage backend
- [ ] Namespace / team API keys

---

## License

MIT
