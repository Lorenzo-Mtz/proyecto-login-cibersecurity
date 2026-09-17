"""Fixtures compartidas por todas las pruebas.

pytest descubre este archivo solo: cualquier prueba puede pedir una fixture
declarandola como parametro, sin importarla.

Todo aqui apunta a un directorio temporal: ninguna prueba toca instance/app.db
ni instance/audit.log reales.
"""
import json
import os
import sqlite3
import sys

import bcrypt
import pytest

# Permite `from src...` al correr pytest desde la raiz del proyecto.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import config
from src.audit import audit_logger

PASSWORD = "ContrasenaValida123"
USERNAME = "ana"


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    """Fabrica de apps aisladas. Devuelve una funcion, no una app.

    Se necesita fabrica y no una app fija porque las pruebas de CSRF piden la
    proteccion encendida y las demas la piden apagada.
    """
    def _make(csrf_enabled=False, **overrides):
        # AUDIT_LOG y SECRET_KEY se parchan en Config y no en app.config porque
        # create_app() los lee (init_audit_log y validate_secret_key) antes de
        # que exista una app que podamos modificar.
        monkeypatch.setattr(config.Config, "DATABASE", str(tmp_path / "test.db"))
        monkeypatch.setattr(config.Config, "AUDIT_LOG", str(tmp_path / "audit.log"))
        # Fija una clave valida para que las pruebas no dependan del .env local.
        monkeypatch.setattr(config.Config, "SECRET_KEY", "x" * 64)

        # init_audit_log() no agrega un segundo handler si ya hay uno (para que
        # el recargador de Flask en debug no duplique cada linea). En un mismo
        # proceso de pytest eso haria que todas las apps escribieran en el log
        # de la primera, asi que se limpian antes de cada una.
        for handler in list(audit_logger.handlers):
            handler.close()
            audit_logger.removeHandler(handler)

        from src.app import create_app

        app = create_app()
        app.config["WTF_CSRF_ENABLED"] = csrf_enabled
        # El test client habla http; con la cookie marcada Secure no la guarda
        # y ninguna prueba con sesion funcionaria.
        app.config["SESSION_COOKIE_SECURE"] = False
        app.config.update(overrides)

        with app.app_context():
            from src.database import init_db

            init_db()

        return app

    return _make


@pytest.fixture
def app(make_app):
    """App lista para usar, con CSRF apagado (ya se verifica en test_csrf.py)."""
    return make_app()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    """Conexion directa a la BD de la prueba, para inspeccionar o preparar datos."""
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


@pytest.fixture
def usuario(db):
    """Crea a 'ana' con una contrasena conocida y devuelve su id."""
    cur = db.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (USERNAME, "ana@example.com",
         bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(12)).decode()),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def eventos(app):
    """Devuelve una funcion que lee el log de auditoria de esta prueba."""
    def _leer():
        ruta = app.config["AUDIT_LOG"]
        if not os.path.exists(ruta):
            return []
        # Los handlers de logging escriben con buffer: hay que vaciarlo antes
        # de leer o los ultimos eventos todavia no estan en el archivo.
        for handler in audit_logger.handlers:
            handler.flush()
        with open(ruta, encoding="utf-8") as f:
            return [json.loads(linea) for linea in f if linea.strip()]

    return _leer


def token_csrf(client, ruta="/login"):
    """Extrae el csrf_token del formulario de una pagina.

    Es lo que hace un navegador: pedir la pagina y reenviar el campo oculto.
    """
    html = client.get(ruta).get_data(as_text=True)
    marca = 'name="csrf_token" value="'
    inicio = html.index(marca) + len(marca)
    return html[inicio:html.index('"', inicio)]
