from flask import current_app

def is_blocked(db, username):
    """True si username acumula LOGIN_MAX_ATTEMPTS o mas fallos en la ventana."""
    ventana = current_app.config["LOGIN_WINDOW_SECONDS"]
    attempts = db.execute(
        "SELECT COUNT(*) FROM login_attempts "
        "WHERE username = ? AND attempted_at > datetime('now', ?)",
        (username, f"-{ventana} seconds")
    ).fetchone()[0]

    return attempts >= current_app.config["LOGIN_MAX_ATTEMPTS"]
    
def record_failed_attempt(db, username):
    """Registra un fallo y borra los que ya salieron de la ventana."""
    ventana = current_app.config["LOGIN_WINDOW_SECONDS"]
    db.execute(
        "INSERT INTO login_attempts (username) VALUES (?)",
        (username,),
    )

    db.execute(
        "DELETE FROM login_attempts WHERE username = ? AND attempted_at <= datetime('now', ?)",
        (username,f"-{ventana} seconds"),
    )

    db.commit()



def reset_attempts(db, username):
    """Borra el historial de fallos de username (WBS 4.1.4)."""
    db.execute(
        "DELETE FROM login_attempts WHERE username = ?",
        (username,),
    )
    db.commit()
