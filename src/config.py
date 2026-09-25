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

    # --- WBS 6.5 - Rotacion del registro (gap G5, amenaza TM-28) ---
    # Un log que crece sin techo es una denegacion de servicio con retardo: al
    # llenar el disco cae el sistema entero, no solo la auditoria. Es la unica
    # de las tres carencias de R18 que se puede cerrar sin salir del proyecto
    # -- la integridad (append-only) y el alerting necesitan infraestructura.
    #
    # Cinco respaldos de 1 MB son 6 MB de historia: sobra para un proyecto sin
    # usuarios, y el numero esta aqui para que una prueba pueda bajarlo a bytes
    # y ver la rotacion de verdad, como se hizo con los demas umbrales.
    AUDIT_LOG_MAX_BYTES = 1024 * 1024
    AUDIT_LOG_BACKUPS = 5

    # --- WBS 3.4.2 - Cookies HttpOnly / Secure / SameSite ---
    # Flask ya marca la cookie de sesion como HttpOnly por default (no es
    # accesible desde JavaScript), pero SECURE y SAMESITE no vienen
    # configurados de forma segura por default: te toca definirlos aqui.
    #
    # Pistas (glosario, seccion 4.4 -- era la 4.3 antes de la renumeracion de 7.2):
    #   - SESSION_COOKIE_SECURE:   ¿debe viajar la cookie solo por HTTPS?
    #   - SESSION_COOKIE_SAMESITE: "Lax", "Strict" o "None" -- ¿cual mitiga
    #     mejor CSRF sin romper la navegacion normal del login?
    #
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"

    # --- WBS 6.2 - Prefijo de la cookie de sesion (gap G2, ASVS V3.3.1) ---
    # El prefijo NO es decorativo: el navegador se niega a aceptar una cookie
    # __Host- que no cumpla las tres condiciones a la vez -- atributo Secure,
    # Path=/ y SIN atributo Domain. Eso la ata a este origen exacto, de modo
    # que un subdominio no la puede SOBRESCRIBIR. Secure protege la lectura;
    # el prefijo protege la escritura, que es un ataque distinto.
    #
    # Las tres condiciones ya se cumplian: Secure arriba, Path=/ por defecto en
    # Flask, y SESSION_COOKIE_DOMAIN sin definir. Solo faltaba el nombre.
    #
    # OJO, y esta es la parte que ninguna prueba puede verificar: el test
    # client de Werkzeug NO implementa las reglas de prefijo, asi que la suite
    # se queda en verde aunque un navegador rechazara la cookie. Y sobre HTTP
    # plano el comportamiento VARIA entre navegadores (hay un issue abierto en
    # el repositorio de RFC 6265bis sobre localhost). Por eso este paquete
    # exige comprobacion manual en el navegador, como la exigio 4.3.6 con la
    # app autenticadora.
    SESSION_COOKIE_NAME = "__Host-session"

    # --- WBS 4.5.4 - Expiracion por inactividad (R9) ---
    # El nombre lo pone Flask y despista: NO es la vida maxima de la sesion,
    # es cuanto sobrevive la cookie SIN peticiones. Flask lo valida contra el
    # timestamp que va dentro de la firma (open_session -> max_age), asi que
    # se hace cumplir del lado del servidor y no depende del Expires que el
    # navegador puede ignorar. Pero SESSION_REFRESH_EACH_REQUEST viene en True
    # por default y vuelve a firmar la cookie en cada peticion: la ventana se
    # desliza, y por esta via un usuario activo no expira nunca.
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)

    # --- WBS 4.5.4 - Vida maxima de la sesion (R9) ---
    # Justo lo que la linea de arriba no hace. Se cuenta desde el login y la
    # actividad NO lo renueva: es el unico limite que una cookie robada no
    # puede estirar con solo usarla. Flask no lo trae; se comprueba en
    # @login_required contra session["login_at"].
    # En segundos y no timedelta, como los demas umbrales del proyecto, para
    # que la prueba pueda bajarlo a segundos y ver el vencimiento de verdad.
    SESSION_ABSOLUTE_LIFETIME_SECONDS = 12*60*60

    # --- WBS 6.6 - Politica del nombre de usuario (gap G6, ASVS V2.1.1/V2.2.1) ---
    # Hasta la Fase 3 el unico control era "que no este vacio", y eso costo un
    # hallazgo concreto: alguien podia registrarse como `mfa:ana`, lo que
    # descarto usar prefijos como espacio de nombres en el contador de intentos
    # (LL20). La regla es una LISTA BLANCA y no una lista negra: se enumera lo
    # que se permite, no lo que se prohibe, porque una lista negra siempre deja
    # fuera el caracter que nadie penso.
    #
    # Los dos puntos quedan fuera a proposito, y eso vuelve seguro el prefijado
    # que LL20 habia descartado (ver 6.11).
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 32
    USERNAME_PATTERN = r"^[a-zA-Z0-9._-]+$"

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
