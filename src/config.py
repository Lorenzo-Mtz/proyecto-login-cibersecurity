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

    # --- WBS 4.1.1 - Politica anti fuerza bruta ---
    # En config y no en auth.py para que la prueba de 4.1.5 pueda bajar la
    # ventana a segundos y verificar que el bloqueo expira.
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 15*60

    # --- WBS 4.2.1 - Vida del token de recuperacion ---
    # Corta porque el token vive en una bandeja de entrada, que es justo el
    # lugar que se compromete. Aqui y no en el codigo para que la prueba de
    # 4.2.7 pueda bajarla a segundos y verificar que el token expira.
    RESET_TOKEN_LIFETIME_SECONDS = 30*60

    # --- WBS 4.3 - Segundo factor por TOTP ---
    # Nombre que la app autenticadora muestra junto a la cuenta.
    MFA_ISSUER = "Login Seguro"

    # 30 segundos es el periodo del RFC 6238, y el que asumen Google
    # Authenticator, Authy y compania. Cambiarlo rompe la compatibilidad con
    # cualquier app estandar: esta aqui para poder leerlo, no para moverlo.
    TOTP_PERIOD = 30

    # Tolerancia de +-1 periodo: acepta el codigo anterior y el siguiente para
    # absorber el reloj desfasado del telefono y el rato que toma teclear.
    # Cada periodo extra TRIPLICA los codigos validos en un instante dado.
    TOTP_VALID_WINDOW = 1

    # Vida de la sesion "pendiente de MFA" (WBS 4.3.4). Corta a proposito: esa
    # cookie representa una contrasena YA VALIDADA esperando el segundo factor,
    # y no tiene por que sobrevivir mas alla del rato que toma sacar el
    # telefono. No basta con no marcarla permanente: mucha gente no cierra
    # nunca el navegador. Aqui y no en el codigo para que una prueba pueda
    # bajarlo a segundos.
    MFA_PENDING_LIFETIME_SECONDS = 5*60
