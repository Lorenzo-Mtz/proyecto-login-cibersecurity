from flask import Flask, flash, redirect, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect

from src.config import Config
from src.database import close_db
from src.routes.auth import auth_bp

# Valor de ejemplo de .env.example: si alguien lo copia sin cambiarlo, la
# clave es publica (esta en el repo).
SECRET_KEY_PLACEHOLDER = "cambia-esto-por-un-valor-aleatorio-largo"
SECRET_KEY_MIN_LENGTH = 32

csrf = CSRFProtect()


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

    app.teardown_appcontext(close_db)
    app.register_blueprint(auth_bp)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash("El formulario expiro o no es valido. Intentalo de nuevo.")
        return redirect(url_for("auth.login"))

    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    return app
