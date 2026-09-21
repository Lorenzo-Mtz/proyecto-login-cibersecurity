-- WBS 3.1.2 - Diseno del esquema SQLite (tabla users)
--
-- Nota: guardamos password_hash, nunca la contrasena en texto plano.
-- El hash se genera en src/routes/auth.py (WBS 3.2.4).


-- WBS 4.3.2 - Columnas del segundo factor (TOTP)
--
-- totp_secret va EN CLARO, al reves que el token de 4.2, y no es un descuido:
-- es el riesgo R12, aceptado a conciencia. La diferencia esta en lo que el
-- servidor tiene que hacer con cada cosa. Con el token de recuperacion solo
-- COMPARA (le llega el token, lo hashea, ve si coincide), asi que le basta el
-- hash. Con TOTP tiene que RECALCULAR: el telefono genero HMAC(secreto, t/30)
-- sin conexion, y para comparar resultados el servidor necesita el secreto
-- entero. No se puede calcular un HMAC con el hash de la llave.
--
-- mfa_enabled es columna propia y no "totp_secret IS NOT NULL" porque el
-- enrolamiento tiene TRES estados, no dos:
--     sin secreto  ->  con secreto sin confirmar  ->  confirmado
-- Inferir el estado de un NULL colapsa los dos ultimos, y el que se pierde es
-- justo el intermedio: quien abre la pagina del QR y cierra la pestana sin
-- escanear quedaria marcado como protegido, y el siguiente login le pediria un
-- codigo que su telefono no puede generar. DEFAULT 0 por la misma razon: una
-- cuenta que ya existia nace fuera de MFA, nunca atrapada dentro.
--
-- last_mfa_timecode guarda el NUMERO DE PERIODO del ultimo codigo aceptado
-- (t/30, el mismo numero que entro al HMAC), NO el codigo. Dos motivos:
--   1. El periodo no es secreto -- es el reloj dividido entre 30 -- mientras
--      que un codigo es una credencial viva hasta 60 segundos por la
--      tolerancia de +-1. Guardar el codigo seria escribir en users justo lo
--      que audit.py tiene prohibido registrar. Hashearlo no ayudaria: seis
--      digitos son un millon de posibilidades y el hash se revierte por fuerza
--      bruta al instante. Hashear solo protege lo que ya tiene entropia.
--   2. Protege mas. Exigir que el periodo nuevo sea ESTRICTAMENTE MAYOR que el
--      guardado rechaza el codigo repetido y ademas invalida los anteriores de
--      la ventana: quien vio un codigo por encima del hombro no puede usar ni
--      ese ni el del periodo previo. Guardar el codigo solo tapa el primero.
-- Esto solo funciona si se actualiza CADA vez que se acepta un codigo.
-- NULL mientras el usuario no haya usado ninguno.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_version INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    last_mfa_timecode INTEGER
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

-- WBS 4.2.1 - Tokens de recuperacion de contrasena emitidos
--
-- Al reves que login_attempts, esta tabla si lleva FOREIGN KEY a users:
-- alla se cuentan intentos contra cuentas que no existen (si no, el bloqueo
-- revelaria cuales existen); aqui un token solo tiene sentido para un usuario
-- real. La verificacion se enciende por conexion en database.py: SQLite la
-- trae apagada por default y sin ella la restriccion no se aplica.
--
-- token_hash guarda el SHA-256 del token, nunca el token (R11).
-- used_at es NULL mientras no se use: guarda cuando se consumio, que un
-- booleano perderia.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id),
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP
);
