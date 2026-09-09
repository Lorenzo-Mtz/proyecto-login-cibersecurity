"""
Rutas de autenticacion: registro, login, logout, dashboard.

Este archivo es el andamiaje de la Fase 1 (ver docs/wbs.md, seccion 3.0).
Las partes marcadas con TODO son la logica de seguridad que te toca
implementar a ti -- son justo los conceptos que ya estudiaste en la Fase 0
y que estan en docs/glossary.md (secciones 4.1 a 4.5).

No borres los comentarios TODO hasta que hayas resuelto ese punto; sirven
como checklist de la Fase 1 del WBS.
"""
from email_validator import validate_email, EmailNotValidError
import bcrypt
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from src.database import get_db
import sqlite3

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
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
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

        

        if len(password.encode('utf-8'))>72:
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))
        
        
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


        if user is None:
            bcrypt.checkpw(password.encode('utf-8'),DUMMY_HASH) #evitar fuga por tiempo de proceso
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))

        credentials_valid = bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')) 

        if not credentials_valid:
            flash("Usuario o contraseña incorrectos")
            return redirect(url_for("auth.login"))

        session.clear()
        session["user_id"] = user["id"]
        flash("Sesión iniciada")
        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    
    return render_template("dashboard.html")
