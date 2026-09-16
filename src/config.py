import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# El .env debe cargarse ANTES de definir Config: los atributos de clase se
# evaluan al importar este modulo, no al crear la app.
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    # --- WBS 4.5.1 - SECRET_KEY obligatoria ---
    # Firma la cookie de sesion y los mensajes flash. Quien la conozca puede
    # fabricar una cookie con cualquier user_id, asi que no hay valor por
    # defecto: create_app() se niega a arrancar si falta o es debil.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    DATABASE = os.path.join(BASE_DIR, "instance", "app.db")

    AUDIT_LOG = os.path.join(BASE_DIR, "instance", "audit.log")

    # --- WBS 3.4.2 - Cookies HttpOnly / Secure / SameSite ---
    # Flask ya marca la cookie de sesion como HttpOnly por default (no es
    # accesible desde JavaScript), pero SECURE y SAMESITE no vienen
    # configurados de forma segura por default: te toca definirlos aqui.
    #
    # Pistas (glosario, seccion 4.3):
    #   - SESSION_COOKIE_SECURE:   ¿debe viajar la cookie solo por HTTPS?
    #   - SESSION_COOKIE_SAMESITE: "Lax", "Strict" o "None" -- ¿cual mitiga
    #     mejor CSRF sin romper la navegacion normal del login?
    #
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(days=14)
