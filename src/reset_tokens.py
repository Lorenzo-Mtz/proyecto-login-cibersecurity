"""Emision de tokens de recuperacion de contrasena (WBS 4.2.3, R11).

Regla del modulo: el token en claro nunca se guarda ni se registra. La BD solo
ve su SHA-256, de modo que quien lea app.db (un backup filtrado, una inyeccion
SQL, un disco robado) tiene hashes y no enlaces de acceso utilizables.

SHA-256 y no bcrypt a proposito: bcrypt es lento para encarecer el diccionario
contra un secreto de baja entropia como una contrasena. Un token de
secrets.token_urlsafe(32) trae 256 bits de aleatoriedad real, asi que no hay
diccionario que probar y la lentitud no compraria nada.
"""
from flask import current_app
import hashlib
import secrets


def issue_token(db, user_id):
    """Emite un token para user_id y lo devuelve en claro (solo para entregarlo).

    El DELETE previo invalida los tokens anteriores del usuario: el nuevo
    reemplaza a los viejos, para que no haya varias credenciales vivas a la vez.
    La traza de que existieron queda en el log de auditoria, no en esta tabla.

    expires_at lo calcula SQLite y no Python: created_at lo pone
    CURRENT_TIMESTAMP (UTC, 'YYYY-MM-DD HH:MM:SS') y mezclar relojes dejaria
    las dos columnas de tiempo en formatos distintos, con comparaciones de
    expiracion que fallan en los bordes.
    """
    db.execute(
        "DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,)
    )
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    vida = current_app.config["RESET_TOKEN_LIFETIME_SECONDS"]

    db.execute(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) "
        "VALUES (?, ?, datetime('now', ?))",
        (user_id, token_hash, f"+{vida} seconds"),
    )
    db.commit()

    return token

def find_valid_token(db, token):
    """Devuelve la fila del token si sirve, o None si no existe, expiro o ya se uso."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return db.execute(
        "SELECT t.id AS token_id, t.user_id, u.username "
        "FROM password_reset_tokens t "
        "JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ? AND t.used_at IS NULL "
        "AND t.expires_at > datetime('now')",
        (token_hash,),
    ).fetchone()
