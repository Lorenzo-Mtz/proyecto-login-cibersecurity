"""
Rutas de autenticacion: registro, login, logout, dashboard.

Este archivo es el andamiaje de la Fase 1 (ver docs/wbs.md, seccion 3.0).
Las partes marcadas con TODO son la logica de seguridad que te toca
implementar a ti -- son justo los conceptos que ya estudiaste en la Fase 0
y que estan en docs/glossary.md (secciones 4.1 a 4.5).

No borres los comentarios TODO hasta que hayas resuelto ese punto; sirven
como checklist de la Fase 1 del WBS.
"""
import bcrypt
from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from src.database import get_db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- TODO (WBS 3.2.2 - Validacion de inputs, server-side) ---
        # ¿Que pasa si username/email/password vienen vacios?
        # ¿El email tiene un formato razonable?
        # ¿password y confirm_password coinciden?
        # Si algo falla: usa flash("mensaje") y haz `return redirect(url_for("auth.register"))`
        # ANTES de seguir, para no continuar con datos invalidos.

        # --- TODO (WBS 3.2.3 - Politica de contrasenas) ---
        # Define una politica minima (ej. longitud minima) y aplicala aqui.
        # Pista: glosario 4.1 (bcrypt, Factor de trabajo) -- bcrypt ya protege
        # contra fuerza bruta en el hash, pero la politica de contrasenas es
        # una capa adicional e independiente.

        # --- TODO (WBS 3.2.4 - Hashing con bcrypt) ---
        # NUNCA guardes `password` en texto plano en la base de datos.
        # Genera el hash con bcrypt (bcrypt.hashpw + bcrypt.gensalt()) y
        # guarda ese resultado (como string) en `password_hash`.
        # Pista: glosario 4.1 -- "bcrypt", "Sal (Salt)".
        password_hash = None  # <-- reemplaza esto por el hash real

        if password_hash is None:
            flash("Registro aun no implementado (ver TODOs de WBS 3.2 en src/routes/auth.py)")
            return redirect(url_for("auth.register"))

        db = get_db()
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()

        flash("Cuenta creada. Ya puedes iniciar sesion.")
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
