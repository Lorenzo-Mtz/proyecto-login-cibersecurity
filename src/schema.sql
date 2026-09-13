-- WBS 3.1.2 - Diseno del esquema SQLite (tabla users)
--
-- Nota: guardamos password_hash, nunca la contrasena en texto plano.
-- El hash se genera en src/routes/auth.py (WBS 3.2.4).

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_version INTEGER NOT NULL DEFAULT 0
);
