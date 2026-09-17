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


-- WBS 4.1.2 - Intentos de login fallidos (ventana deslizante)
--
-- Tabla propia y no columnas en users: se cuentan tambien los intentos
-- contra cuentas que no existen. Si solo contaramos usuarios reales, el
-- bloqueo revelaria cuales existen (R10).

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
    ON login_attempts (username, attempted_at);
