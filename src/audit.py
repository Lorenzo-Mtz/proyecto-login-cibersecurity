import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone

from flask import request

# Catalogo cerrado de eventos (WBS 4.4.1, R14). Los de 4.2-4.3 se agregan
# cuando se implementen esos paquetes.
EVENTS = {
    "register_success": "Cuenta creada",
    "register_failure": "Registro rechazado: usuario o email ya existe",
    "login_success": "Login correcto",
    "login_failure": "Credenciales incorrectas",
    "logout": "Cierre de sesion con cookie vigente",
    "session_rejected": "Cookie con session_version vieja o de usuario inexistente",
    "csrf_failure": "POST con token CSRF ausente o invalido",
    "login_blocked": "Login rechazado por limite de intentos",
    "password_reset_requested": "Solicitud de recuperacion de contrasena",
    "password_reset_failure": "Token de recuperacion invalido, expirado o ya usado",
    "password_reset_success": "Contrasena cambiada por recuperacion",
    # WBS 4.3. Nunca se registra el secreto TOTP ni el codigo: la firma de
    # audit() no tiene por donde pasarlos (4.4.3, R14).
    "mfa_activated": "Segundo factor activado tras validar el primer codigo",
    # Alguien acerto la contrasena de esta cuenta y quedo detenido en el
    # segundo factor. Es la senal que MFA existe para producir: una rafaga de
    # estos SIN un login_success detras significa que la contrasena ya esta
    # comprometida. Por eso es un evento propio y no un login_failure.
    "mfa_required": "Contrasena correcta; sesion pendiente del segundo factor",
    "mfa_failure": "Codigo TOTP incorrecto, reutilizado o fuera de la ventana",
    # WBS 4.5.4. Lo emite solo el tope absoluto. La expiracion por inactividad
    # no puede registrarse: Flask descarta la cookie vencida antes de la vista
    # y la sesion llega vacia, sin user_id que anotar. Sin umbral en el texto:
    # si el tope cambia, el catalogo no miente.
    "session_expired": "Cookie rechazada por superar la vida maxima de la sesion",
    # WBS 6.4. Un fallo no previsto es informacion para quien lo provoca (LL15)
    # y hasta ahora no dejaba rastro: audit() solo se llamaba en los caminos
    # que el codigo esperaba. La descripcion NO lleva detalle del error a
    # proposito -- la firma de audit() no tiene por donde pasarlo, y esa es la
    # garantia (4.4.3, R14).
    "server_error": "Fallo no controlado durante una peticion",
}

MAX_FIELD_LENGTH = 64

audit_logger = logging.getLogger("audit")


def init_audit_log(app):
    """Conecta audit_logger al archivo de auditoria. Se llama desde create_app()."""
    # Si ya hay handler, no se agrega otro: cada uno escribiria su propia copia.
    if audit_logger.handlers:
        return

    ruta = app.config["AUDIT_LOG"]
    os.makedirs(os.path.dirname(ruta), exist_ok=True)

    # delay=True: el archivo se abre hasta el primer evento, no al arrancar
    # (con debug=True, Flask levanta dos procesos).
    #
    # WBS 6.5 (gap G5): rotacion por tamano. Sin ella el archivo crece sin
    # techo y llenar el disco es una denegacion de servicio (TM-28). Rota, no
    # borra: se conservan AUDIT_LOG_BACKUPS archivos, asi que la historia
    # reciente sobrevive. No cierra R18 -- el log sigue siendo escribible por
    # quien alcance el disco -- pero cierra una de sus tres carencias.
    handler = logging.handlers.RotatingFileHandler(
        ruta,
        maxBytes=app.config["AUDIT_LOG_MAX_BYTES"],
        backupCount=app.config["AUDIT_LOG_BACKUPS"],
        encoding="utf-8",
        delay=True,
    )
    # Sin prefijos de logging: la linea es exactamente el JSON (la fecha va dentro).
    handler.setFormatter(logging.Formatter("%(message)s"))

    audit_logger.addHandler(handler)
    audit_logger.propagate = False
    # Sin esto el logger hereda WARNING del raiz y descarta los INFO en silencio.
    audit_logger.setLevel(logging.INFO)


def audit(event, user_id=None, username=None):
    """Escribe un evento del catalogo como una linea JSON.

    La firma no acepta campos libres: no hay forma de pasarle por accidente
    una contrasena, un token o un codigo MFA (WBS 4.4.3, R14).
    """
    if event not in EVENTS:
        raise ValueError(f"Evento de auditoria no catalogado: {event}")

    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "user_id": user_id,
        "username": username[:MAX_FIELD_LENGTH] if username else None,
        # remote_addr, no X-Forwarded-For: ese encabezado lo escribe el cliente.
        "ip": request.remote_addr,
        "path": request.path,
    }
    # json.dumps escapa saltos de linea y comillas: un username malicioso no
    # puede fabricar una segunda linea en el log (log injection).
    audit_logger.info(json.dumps(record, ensure_ascii=False))