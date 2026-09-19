import os
import sqlite3

from flask import current_app, g


def get_db():
    """Devuelve una conexion SQLite reusada durante el request actual."""
    if "db" not in g:
        os.makedirs(os.path.dirname(current_app.config["DATABASE"]), exist_ok=True)
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Crea las tablas definidas en schema.sql si todavia no existen."""
    db = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()
