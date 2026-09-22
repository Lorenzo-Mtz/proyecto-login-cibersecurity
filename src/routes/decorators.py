from functools import wraps
import time

from flask import current_app, flash, g, redirect, session, url_for

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

        # WBS 4.5.4 - Vida maxima de la sesion (R9). Va ANTES del SELECT: una
        # cookie vencida no tiene por que costar una consulta. Como efecto
        # secundario decide el evento cuando la cookie esta vencida Y trae una
        # session_version vieja: gana session_expired, que es lo primero que
        # dejo de ser cierto.
        #
        # Esto NO duplica PERMANENT_SESSION_LIFETIME. Aquel cuenta desde la
        # ultima peticion, lo aplica Flask solo y se desliza con el uso; este
        # cuenta desde el login y la actividad NO lo renueva. Es el unico de
        # los dos que una cookie robada no puede estirar usandola.
        #
        # El 0 por default es el fail-closed, sin una rama aparte: una sesion
        # sin login_at da una antiguedad enorme y se rechaza sola. Asi queda
        # cubierta tanto la cookie emitida antes de 4.5.4 como cualquier punto
        # futuro que abra sesion y olvide poner la marca.
        vida = current_app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"]
        nacida = session.get("login_at", 0)

        if time.time() - nacida > vida:
            # Sin username: todavia no hay SELECT. Igual que en session_rejected.
            audit("session_expired", user_id=user_id)
            session.clear()
            # Mensaje generico a proposito. Decir "tu sesion caduco" le
            # confirmaria a quien usa una cookie robada que la cookie era
            # buena y que solo llego tarde; asi se lee igual sea cual sea el
            # motivo del rechazo.
            flash("Vuelve a iniciar sesion.")
            return redirect(url_for("auth.login"))

        db = get_db()
        # Columnas explicitas y NO "SELECT *": desde 4.3 la fila de users lleva
        # totp_secret. Con un asterisco, el secreto del segundo factor quedaria
        # en g.user en cada peticion protegida, al alcance de cualquier
        # plantilla que alguien escriba despues. mfa_enabled si viene, porque
        # es un indicador de estado y no un secreto.
        user = db.execute(
            "SELECT id, username, session_version, mfa_enabled FROM users WHERE id = ?",
            (user_id,),
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