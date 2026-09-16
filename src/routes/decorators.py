from functools import wraps

from flask import g, redirect, session, url_for

from src.database import get_db
from src.audit import audit


def login_required(view):
    """Protege una vista: exige una sesion valida y deja el usuario en g.user.

    Uso (el orden importa, route va ARRIBA):
        @auth_bp.route("/ruta")
        @login_required
        def vista(): ...
    """
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("auth.login"))

        db = get_db()
        user = db.execute(
            "SELECT id, username, session_version FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        # Invalidacion server-side (R9): una cookie emitida antes del ultimo
        # logout trae una session_version vieja y se rechaza.
        if user is None or session.get("session_version") != user["session_version"]:
            audit("session_rejected", user_id=user_id)
            session.clear()
            return redirect(url_for("auth.login"))

        g.user = user
        return view(*args, **kwargs)

    return wrapped_view