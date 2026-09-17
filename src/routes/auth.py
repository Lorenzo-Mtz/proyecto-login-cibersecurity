from email_validator import validate_email, EmailNotValidError
import bcrypt
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from src.database import get_db
import sqlite3
from src.routes.decorators import login_required
from src.audit import audit
from src.throttle import is_blocked, record_failed_attempt, reset_attempts

SALT = 12
DUMMY_HASH = bcrypt.hashpw("dummypassword".encode('utf-8'),bcrypt.gensalt(SALT))

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form.get("username", "").strip()
        if not username:
            flash("El usuario esta vacio")
            return redirect(url_for("auth.register"))
        
        email = request.form.get("email", "").strip()
        
        if not email:
            flash("El correo esta vacio.")
            return redirect(url_for("auth.register"))
        try: 
            email_validado = validate_email(email, check_deliverability=False)
        except EmailNotValidError:
            flash("El formato del correo es erroneo.")
            return redirect(url_for("auth.register"))

        email = email_validado.normalized.lower()

        
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not (12 <= len(password) <= 64):
            flash("La contraseña no cumple con las condiciones: 1. Minimo 12 caracteres, 2. Máximo 64 caracteres")
            return redirect(url_for("auth.register"))
        if not confirm_password:
            flash("La confirmación de contraseña esta vacia")
            return redirect(url_for("auth.register"))
        if password != confirm_password:
            flash("La confirmación de contraseña no coincide")
            return redirect(url_for("auth.register"))

        if len(password.encode("utf-8"))>72:
            flash("La contraseña es demasiado larga, prueba incluir menos caracteres especiales.")
            return redirect(url_for("auth.register"))
        password_hash = (bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(SALT))).decode("utf-8")

        db = get_db()
        try:
            cur = db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            db.commit()
            audit("register_success", user_id=cur.lastrowid, username=username)
        except sqlite3.IntegrityError:
            audit("register_failure", username=username)
            db.rollback()
            flash("No se pudo crear la cuenta. Verifica los datos e inténtalo de nuevo.")
            return redirect(url_for("auth.register"))
        

        flash("Cuenta creada. Ya puedes iniciar sesión.")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()

        # WBS 4.1.3 - Antes de mirar si la cuenta existe: la decision ya esta
        # tomada y consultar users seria trabajo tirado. El checkpw contra
        # DUMMY_HASH se ejecuta aunque su resultado se ignore, para que la
        # respuesta bloqueada tarde lo mismo que un fallo normal (R10: sin el,
        # la latencia delata que la cuenta existe y esta bajo ataque).
        # No se registra el intento: retornar sin contarlo impide que un
        # atacante renueve el bloqueo de una victima indefinidamente.
        if is_blocked(db, username):
            bcrypt.checkpw(password.encode('utf-8'), DUMMY_HASH)
            audit("login_blocked", username=username)
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))

        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if len(password.encode('utf-8')) > 72:
            audit("login_failure", username=username)
            record_failed_attempt(db, username)
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))

        if user is None:
            bcrypt.checkpw(password.encode('utf-8'), DUMMY_HASH)  # evitar fuga por tiempo de proceso
            audit("login_failure", username=username)
            record_failed_attempt(db, username)
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))

        credentials_valid = bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8'))

        if not credentials_valid:
            audit("login_failure", username=username)
            record_failed_attempt(db, username)
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))

        # WBS 4.1.4 - Un login correcto borra el historial: el usuario que fallo
        # cuatro veces y acerto no arrastra esos fallos al proximo intento.
        reset_attempts(db, username)
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["session_version"] = user["session_version"]
        audit("login_success", user_id=user["id"], username=user["username"])
        flash("Sesión iniciada")
        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")
    if user_id:
        # Invalida en el servidor todas las cookies de este usuario (R9), solo si esta
        # cookie trae la version vigente: una cookie vieja no puede cerrar sesiones nuevas.
        db = get_db()
        cur = db.execute(
            "UPDATE users SET session_version = session_version + 1 "
            "WHERE id = ? AND session_version = ?",
            (user_id, session.get("session_version")),
        )
        db.commit()
        if cur.rowcount == 1:
            audit("logout", user_id=user_id)
        else:
            audit("session_rejected", user_id=user_id)
    session.clear()

    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=g.user["username"])
