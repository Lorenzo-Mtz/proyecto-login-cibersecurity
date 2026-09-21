from email_validator import validate_email, EmailNotValidError
import bcrypt
from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request,
    session, url_for,
)
from src.database import get_db
import sqlite3
import time
from src.routes.decorators import login_required
from src.audit import audit
from src.throttle import is_blocked, record_failed_attempt, reset_attempts
from src.reset_tokens import issue_token, find_valid_token
from src.mailer import send_password_reset
from src.mfa import generar_secreto, qr_data_uri, uri_de_aprovisionamiento, verificar_codigo


SALT = 12
DUMMY_HASH = bcrypt.hashpw("dummypassword".encode('utf-8'),bcrypt.gensalt(SALT))

auth_bp = Blueprint("auth", __name__)

def validar_password(password, confirm_password):
    if not (12 <= len(password) <= 64):
        flash("La contraseña no cumple con las condiciones: 1. Minimo 12 caracteres, 2. Máximo 64 caracteres")
        return False
    if not confirm_password:
        flash("La confirmación de contraseña esta vacia")
        return False
    if password != confirm_password:
        flash("La confirmación de contraseña no coincide")
        return False

    if len(password.encode("utf-8"))>72:
        flash("La contraseña es demasiado larga, prueba incluir menos caracteres especiales.")
        return False
    return True


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

        if not validar_password(password,confirm_password):
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

        # WBS 4.3.4 - La contrasena es correcta, pero AQUI TODAVIA NO HAY
        # SESION. La sesion "pendiente" no lleva user_id, que es la unica clave
        # que @login_required mira: por eso queda rechazada de las rutas
        # protegidas sin una linea de autorizacion nueva.
        #
        # Va en la cookie y no en la BD porque es estado de ESTA conversacion
        # con ESTE navegador, no de la cuenta. La cookie de Flask va firmada,
        # asi que un cliente no puede escribirse a si mismo "ya puse la
        # contrasena"; que sea legible da igual, aqui no hay ningun secreto.
        #
        # Sin session.permanent: cookie de sesion de navegador, no de 14 dias.
        #
        # OJO con lo que NO esta aqui: reset_attempts. Si un acierto de
        # contrasena borrara los fallos de 4.1, quien tenga la contrasena pero
        # no el telefono podria probar codigos de cinco en cinco, volviendo a
        # loguearse entre tanda y tanda, y el limite de intentos del segundo
        # factor no existiria. Se reinicia en mfa_verify(), cuando el usuario
        # ya demostro las DOS cosas.
        if user["mfa_enabled"]:
            session.clear()
            session["pending_mfa_user_id"] = user["id"]
            # La marca de tiempo le pone un limite propio a la pendiente, que
            # no depende de que el usuario cierre el navegador. El cliente no
            # la puede retrasar: la firma se lo impide.
            session["pending_mfa_at"] = int(time.time())
            audit("mfa_required", user_id=user["id"], username=user["username"])
            return redirect(url_for("auth.mfa_verify"))

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
    return render_template(
        "dashboard.html",
        username=g.user["username"],
        mfa_enabled=g.user["mfa_enabled"],
    )


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        db = get_db()

        email = request.form.get("email", "").strip()
        if not email:
            flash("El correo esta vacio.")
            return redirect(url_for("auth.forgot_password"))
        try:
            email_validado = validate_email(email, check_deliverability=False)
        except EmailNotValidError:
            flash("El formato del correo es erroneo.")
            return redirect(url_for("auth.forgot_password"))

        email = email_validado.normalized.lower()

        user = db.execute(
            "SELECT id, username FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user is not None:
            token = issue_token(db, user["id"])
            enlace = url_for("auth.reset_password", token=token, _external=True)
            send_password_reset(email, enlace)
            audit("password_reset_requested", user_id=user["id"], username=user["username"])
        else:
            audit("password_reset_requested")

        flash("Si el correo está registrado, enviamos un enlace para restablecer tu contraseña.")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>")
def reset_password(token):
    return render_template("reset_password.html", token=token)


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password_submit():
    db = get_db()
    read_token = request.form.get("token", "")

    reset = find_valid_token(db, read_token)

    # Inexistente, expirado y ya usado caen los tres aqui, a proposito: el
    # mensaje no distingue cual fue (R11).
    if reset is None:
        audit("password_reset_failure")
        flash("El enlace no es valido o expiro. Solicita uno nuevo.")
        return redirect(url_for("auth.forgot_password"))

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not validar_password(password, confirm_password):
        return redirect(url_for("auth.reset_password", token=read_token))

    password_hash = (bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(SALT))).decode("utf-8")

    # Cuatro cambios y un solo commit: contrasena + session_version, token usado
    # y contador de intentos. Si la contrasena cambiara y el token quedara sin
    # marcar, el enlace del correo seguiria abriendo la cuenta.
    #
    # La contrasena y session_version van en la MISMA sentencia (WBS 4.2.6, R9):
    # cambiar la credencial e invalidar las sesiones abiertas son una sola
    # decision, y juntas no puede ocurrir una sin la otra. A diferencia de
    # logout(), aqui no se exige "AND session_version = ?": quien probo control
    # del correo puede invalidar todo sin presentar ninguna cookie.
    db.execute(
        "UPDATE users SET password_hash = ?, session_version = session_version + 1 "
        "WHERE id = ?",
        (password_hash, reset["user_id"]),
    )

    db.execute(
        "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
        (reset["token_id"],),
    )

    # reset_attempts hace su propio commit: va al final, cuando los UPDATE de
    # arriba ya estan en la transaccion, para que los cuatro cambios entren juntos.
    reset_attempts(db, reset["username"])

    db.commit()
    audit("password_reset_success", user_id=reset["user_id"], username=reset["username"])
    flash("Tu contrasena fue actualizada. Ya puedes iniciar sesion.")
    return redirect(url_for("auth.login"))


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    """Enrolamiento del segundo factor (WBS 4.3.3).

    La regla del paquete: MFA se activa SOLO despues de que el usuario
    demuestra que su app autenticadora ya genera codigos validos. Activarlo al
    mostrar el QR dejaria fuera de su cuenta a quien cierre la pestana sin
    escanear, y la unica salida seria editar la BD a mano (R13: no hay codigos
    de respaldo).

    El control de acceso es @login_required y nada mas: como el enrolamiento
    ocurre despues del login, no hay que escribir autorizacion nueva.
    """
    db = get_db()
    # g.user no trae totp_secret a proposito (ver el SELECT de login_required),
    # asi que aqui se pide explicitamente y solo donde hace falta.
    user = db.execute(
        "SELECT id, username, totp_secret, mfa_enabled FROM users WHERE id = ?",
        (g.user["id"],),
    ).fetchone()

    if user["mfa_enabled"]:
        flash("El segundo factor ya esta activo en esta cuenta.")
        return redirect(url_for("auth.dashboard"))

    # El secreto se guarda en la BD con mfa_enabled = 0 -- ese es el estado
    # intermedio para el que existe la columna -- y NO en la sesion: la cookie
    # de Flask va firmada, no cifrada, asi que cualquiera que la tenga puede
    # leer su contenido, y ahi dentro estaria el segundo factor completo.
    #
    # Si ya hay un secreto pendiente se reutiliza en lugar de generar otro: si
    # cambiara en cada recarga, el QR que el usuario acaba de escanear dejaria
    # de servir y los codigos de su telefono nunca coincidirian.
    secret = user["totp_secret"]
    if secret is None:
        secret = generar_secreto()
        db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
        db.commit()

    if request.method == "POST":
        # Sin ultimo_timecode: es el primer codigo de esta cuenta.
        timecode = verificar_codigo(secret, request.form.get("codigo", ""))

        if timecode is None:
            flash("El codigo no es correcto. Revisa que la hora de tu telefono este sincronizada.")
            return redirect(url_for("auth.mfa_setup"))

        # last_mfa_timecode tambien, no solo mfa_enabled: el codigo que
        # confirma el enrolamiento es un codigo valido que acaba de usarse. Si
        # no quedara consumido, serviria otra vez para el primer login, treinta
        # segundos despues.
        db.execute(
            "UPDATE users SET mfa_enabled = 1, last_mfa_timecode = ? WHERE id = ?",
            (timecode, user["id"]),
        )
        db.commit()
        audit("mfa_activated", user_id=user["id"], username=user["username"])
        flash("Segundo factor activado. La proxima vez que inicies sesion se te pedira un codigo.")
        return redirect(url_for("auth.dashboard"))

    uri = uri_de_aprovisionamiento(secret, user["username"])
    return render_template("mfa_setup.html", qr=qr_data_uri(uri), secret=secret)


@auth_bp.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    """Segundo paso del login (WBS 4.3.4).

    Sin @login_required a proposito: quien llega aqui TODAVIA no tiene sesion.
    El guard de esta ruta es la sesion pendiente, que ademas caduca sola.
    """
    user_id = session.get("pending_mfa_user_id")
    emitida = session.get("pending_mfa_at", 0)
    vida = current_app.config["MFA_PENDING_LIFETIME_SECONDS"]

    if not user_id or time.time() - emitida > vida:
        session.clear()
        flash("Vuelve a iniciar sesion.")
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute(
        "SELECT id, username, session_version, totp_secret, mfa_enabled, "
        "last_mfa_timecode FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    # La cuenta pudo borrarse, o desactivar MFA, entre los dos pasos. Sin esta
    # comprobacion, un mfa_enabled en 0 dejaria totp_secret en NULL y la
    # verificacion reventaria con un 500 -- y un 500 en un flujo de
    # autenticacion es informacion para quien lo provoca (LL15).
    if user is None or not user["mfa_enabled"]:
        session.clear()
        flash("Vuelve a iniciar sesion.")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        # WBS 4.3.5 - Limite de intentos. Seis digitos son un millon de
        # combinaciones: sin limite, un script las prueba todas.
        #
        # El guard va ANTES de verificar, como en login(): la decision ya esta
        # tomada. Lo que NO se copia de login() es el bcrypt contra DUMMY_HASH:
        # alla iguala los ~330 ms de las dos ramas, y aqui verificar un TOTP
        # cuesta microsegundos en los dos casos, asi que no hay latencia que
        # igualar y seria codigo muerto de verdad.
        #
        # Contador compartido con el de la contrasena (misma clave). La
        # alternativa -contador propio para los codigos- se anoto como deuda:
        # es mejor de usabilidad e igual de segura, pero exige tocar el esquema
        # de 4.1 y throttle.py.
        if is_blocked(db, user["username"]):
            # Se audita pero NO se cuenta. Contarlo dejaria mantener la cuenta
            # bloqueada para siempre con una peticion cada quince minutos
            # (R10). En el log en cambio es de las lineas mas valiosas que hay:
            # significa que alguien TIENE la contrasena y lleva rato
            # estrellandose contra el segundo factor.
            audit("login_blocked", user_id=user["id"], username=user["username"])
            flash("Demasiados intentos fallidos. Intentalo de nuevo en unos minutos.")
            return redirect(url_for("auth.mfa_verify"))

        timecode = verificar_codigo(
            user["totp_secret"],
            request.form.get("codigo", ""),
            user["last_mfa_timecode"],
        )

        # Incorrecto, fuera de la ventana y ya usado caen los tres aqui, con el
        # mismo mensaje: distinguir "ya se uso" confirmaria que ese codigo fue
        # valido alguna vez.
        if timecode is None:
            audit("mfa_failure", user_id=user["id"], username=user["username"])
            record_failed_attempt(db, user["username"])
            flash("El codigo no es correcto.")
            return redirect(url_for("auth.mfa_verify"))

        # El periodo se guarda SIEMPRE que se acepta un codigo: si no, la
        # proteccion contra reutilizacion solo funcionaria a ratos.
        db.execute(
            "UPDATE users SET last_mfa_timecode = ? WHERE id = ?",
            (timecode, user["id"]),
        )

        # AQUI se reinicia el contador de 4.1, y no al validar la contrasena:
        # es el punto en el que el usuario demostro los dos factores.
        # reset_attempts hace su propio commit y arrastra el UPDATE de arriba,
        # asi que el codigo queda consumido en la misma transaccion en la que
        # se abre la sesion, nunca una cosa sin la otra.
        reset_attempts(db, user["username"])
        db.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["session_version"] = user["session_version"]
        # login_success y no un evento aparte: en los dos caminos significa
        # exactamente lo mismo, que se creo una sesion.
        audit("login_success", user_id=user["id"], username=user["username"])
        flash("Sesión iniciada")
        return redirect(url_for("auth.dashboard"))

    return render_template("mfa_verify.html")
