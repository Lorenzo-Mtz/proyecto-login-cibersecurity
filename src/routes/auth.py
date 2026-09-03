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
            validate_email(email,check_deliverability=False)
        except EmailNotValidError:
            flash("El formato del correo es erroneo.")
            return redirect(url_for("auth.register"))

        
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
        password_hash = (bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))).decode("utf-8")

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

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # --- TODO (WBS 3.3.2 - Verificacion de credenciales) ---
        # Si `user` existe, compara `password` contra `user["password_hash"]`
        # usando bcrypt.checkpw(...). No uses `==` para comparar contrasenas.
        credentials_valid = False  # <-- reemplaza con el resultado real

        # --- TODO (WBS 3.3.3 - Mensajes de error genericos) ---
        # IMPORTANTE: si el usuario no existe Y si la contrasena es
        # incorrecta, el mensaje debe ser EXACTAMENTE el mismo texto y
        # tomar (aprox.) el mismo tiempo en responder. Si el mensaje
        # cambia segun el caso, estas filtrando informacion.
        # Pista: glosario 4.2 -- "Enumeracion de usuarios" (Username Enumeration).
        if not credentials_valid:
            flash("Usuario o contrasena incorrectos")
            return redirect(url_for("auth.login"))

        # --- TODO (WBS 3.4.1 - Creacion de sesion) ---
        # Si las credenciales son validas, marca al usuario como logeado.
        # Pista: session["user_id"] = user["id"]
        # No lo hagas todavia si `credentials_valid` es un valor fijo (arriba) --
        # primero implementa la verificacion real.

        flash("Login aun no implementado (ver TODOs de WBS 3.3/3.4 en src/routes/auth.py)")
        return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    # --- TODO (WBS 3.5.1 - Invalidacion real de sesion) ---
    # No basta con que el navegador "olvide" la sesion: hay que invalidarla
    # tambien del lado del servidor. Pista: session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
def dashboard():
    # --- TODO (proteccion de ruta) ---
    # Esta ruta deberia requerir sesion activa. Si no hay session["user_id"],
    # redirige a login en vez de mostrar el dashboard.
    return render_template("dashboard.html")
