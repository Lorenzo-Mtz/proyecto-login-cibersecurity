from dotenv import load_dotenv
from flask import Flask, redirect, url_for

from src.config import Config
from src.database import close_db
from src.routes.auth import auth_bp

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.teardown_appcontext(close_db)
    app.register_blueprint(auth_bp)

    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    return app
