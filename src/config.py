import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    # Usada para firmar la cookie de sesion y los mensajes flash.
    # Se carga desde el archivo .env (ver .env.example) via python-dotenv.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-inseguro-cambiame")

    DATABASE = os.path.join(BASE_DIR, "instance", "app.db")

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
    # TODO: agrega aqui las variables que falten, ej.:
    # SESSION_COOKIE_SECURE = ...
    # SESSION_COOKIE_SAMESITE = ...
    # PERMANENT_SESSION_LIFETIME = ...  (opcional: expiracion de sesion)
