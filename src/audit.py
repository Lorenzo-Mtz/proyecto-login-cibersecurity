import json
import logging
import os
from datetime import datetime, timezone

from flask import request

# Catalogo cerrado de eventos (WBS 4.4.1, R14). Los de 4.1-4.3 se agregan
# cuando se implementen esos paquetes.
EVENTS = {
    "register_success": "Cuenta creada",
    "register_failure": "Registro rechazado: usuario o email ya existe",
    "login_success": "Login correcto",
    "login_failure": "Credenciales incorrectas",
    "logout": "Cierre de sesion con cookie vigente",
    "session_rejected": "Cookie con session_version vieja o de usuario inexistente",
    "csrf_failure": "POST con token CSRF ausente o invalido",
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
    handler = logging.FileHandler(ruta, encoding="utf-8", delay=True)
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
