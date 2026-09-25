from flask import (
    Flask, current_app, flash, redirect, render_template, session, url_for,
)
from werkzeug.exceptions import HTTPException
from flask_wtf.csrf import CSRFError, CSRFProtect

from src.config import Config
from src.database import close_db
from src.routes.auth import auth_bp
from src.audit import audit, init_audit_log

# Valor de ejemplo de .env.example: si alguien lo copia sin cambiarlo, la
# clave es publica (esta en el repo).
SECRET_KEY_PLACEHOLDER = "cambia-esto-por-un-valor-aleatorio-largo"
SECRET_KEY_MIN_LENGTH = 32

csrf = CSRFProtect()


# --- WBS 6.1 - Cabeceras de seguridad (G1) ---
#
# Se emiten en TODA respuesta y no solo en las paginas: un 302 o un 404 tambien
# llegan al navegador, y tambien se pueden enmarcar o esnifar.
#
# OJO: after_request NO se ejecuta cuando una excepcion no controlada se
# propaga. Hasta que 6.4 agregue el manejador de 500, esa respuesta sale sin
# estas cabeceras. Esta anotado ahi a proposito.
#
# NO se emite Strict-Transport-Security. No es un olvido: HSTS sobre HTTP plano
# lo ignoran los navegadores, y si alguna vez llegara a tomar efecto sin que
# haya TLS dejaria la aplicacion inalcanzable. Entra con G14, junto al
# despliegue real. Por eso V3.4.1 sigue en fail despues de este paquete.
SECURITY_HEADERS = {
    # Sin JavaScript propio y sin recursos externos, la politica puede ser
    # estricta de verdad: no hace falta 'unsafe-inline' en ninguna directiva.
    # Las plantillas solo cargan static/style.css, del mismo origen.
    #
    # img-src con data: NO es opcional. El QR del enrolamiento se embebe como
    # data: URI (WBS 4.3); con solo default-src 'self' el navegador lo bloquea,
    # y el sintoma es traicionero: la pagina carga bien y el QR no aparece.
    #
    # Permitir data: AQUI es angosto y no contradice a V1.2.2: un data: en un
    # <script> seria un vector de XSS, en un <img> no lo es. Ponerlo en
    # default-src si abriria el agujero.
    #
    # base-uri y form-action NO los cubre default-src, y son los que mas se
    # olvidan. form-action 'self' impide que un formulario inyectado envie las
    # credenciales a otro sitio.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    # Impide que el navegador adivine el tipo de contenido y termine
    # interpretando como HTML o script algo servido como otra cosa.
    "X-Content-Type-Options": "nosniff",
    # Redundante con frame-ancestors 'none' en navegadores modernos, y se
    # mantiene para los que no implementan esa directiva. Cuesta una linea.
    "X-Frame-Options": "DENY",
    # no-referrer, y no strict-origin-when-cross-origin que es la recomendacion
    # general: mientras el token de recuperacion viaje en el path, esta es la
    # unica que corta del todo la fuga por Referer (amenaza TM-34). Se vuelve a
    # valorar cuando G10 saque el token de la URL.
    "Referrer-Policy": "no-referrer",
}


def validate_secret_key(secret_key):
    if not secret_key:
        problem = "no esta definida"
    elif secret_key == SECRET_KEY_PLACEHOLDER:
        problem = "tiene el valor de ejemplo de .env.example"
    elif len(secret_key) < SECRET_KEY_MIN_LENGTH:
        problem = f"tiene menos de {SECRET_KEY_MIN_LENGTH} caracteres"
    else:
        return

    raise RuntimeError(
        f"SECRET_KEY {problem}. Copia .env.example a .env y genera un valor con: "
        'python -c "import secrets; print(secrets.token_hex(32))"'
    )


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    validate_secret_key(app.config["SECRET_KEY"])
    csrf.init_app(app)
    init_audit_log(app)

    app.teardown_appcontext(close_db)
    app.register_blueprint(auth_bp)

    # Asignacion directa y no setdefault: una cabecera de seguridad no deberia
    # poder quedarse fuera porque una vista escribio la suya.
    @app.after_request
    def add_security_headers(response):
        for nombre, valor in SECURITY_HEADERS.items():
            response.headers[nombre] = valor
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        audit("csrf_failure")
        flash("El formulario expiro o no es valido. Intentalo de nuevo.")
        return redirect(url_for("auth.login"))

    # --- WBS 6.4 - Manejo global de errores (gap G4, TM-14, ASVS A10) ---
    # Hasta aqui el unico errorhandler era el de CSRF, asi que un 404 devolvia
    # la pagina por defecto de Werkzeug y un 500 imprevisto, con debug=True, el
    # traceback entero: codigo fuente, variables locales y una consola
    # interactiva. Eso es el ejemplo canonico de "errores que exponen
    # informacion" del propio OWASP.
    @app.errorhandler(404)
    def handle_not_found(e):
        # No se audita: un 404 es ruido de fondo de cualquier aplicacion
        # publica, y registrarlo llenaria el log sin decir nada (LL16).
        return render_template("error.html", codigo=404,
                               mensaje="La pagina que buscas no existe."), 404

    @app.errorhandler(Exception)
    def handle_unexpected(e):
        # Las excepciones HTTP (404, 405, 413...) se dejan pasar a su manejador
        # propio; aqui solo entra lo que nadie previo.
        if isinstance(e, HTTPException):
            return e

        # Se audita SIN el detalle del error: la firma de audit() no acepta
        # campos libres, asi que ni por accidente puede filtrar el traceback a
        # un archivo que alguien lea despues (R14). El detalle se pierde a
        # proposito -- diagnosticar es trabajo del stderr del servidor.
        audit("server_error", user_id=session.get("user_id"))
        current_app.logger.exception("Fallo no controlado")
        return render_template("error.html", codigo=500,
                               mensaje="Algo salio mal. Intentalo de nuevo."), 500

    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    return app
