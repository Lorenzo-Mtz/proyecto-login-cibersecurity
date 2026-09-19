"""Entrega simulada del enlace de recuperacion (WBS 4.2.4).

Este modulo NO envia correo. Imprime el enlace en la consola del servidor de
desarrollo, que es el sustituto de la bandeja de entrada mientras no haya SMTP.

Es el punto de costura del flujo: el dia que haya correo real se reemplaza el
cuerpo de send_password_reset() y ningun otro archivo cambia, porque la funcion
solo recibe dos cadenas ya armadas y no sabe de tokens ni de usuarios.

Se imprime con print y no con current_app.logger a proposito: el mensaje lleva
un token de acceso dentro, y el logger es un sistema de handlers que alguien
puede reconfigurar hacia un archivo. print va al terminal y solo al terminal.
Por la misma razon el enlace nunca entra a audit() ni a la respuesta HTTP.
"""
from flask import current_app


def send_password_reset(email, enlace):
    """Muestra en consola el correo que se enviaria con el enlace de recuperacion.

    La vigencia se lee de la configuracion y no se escribe a mano: si cambia
    RESET_TOKEN_LIFETIME_SECONDS, el mensaje no puede seguir prometiendo otra.
    """
    minutos = current_app.config["RESET_TOKEN_LIFETIME_SECONDS"] // 60
    print("==========================================")
    print("[DEV] Correo simulado - recuperacion de contrasena")
    print(f"Para: {email}")
    print(f"Enlace: {enlace}")
    print(f"Vigencia: {minutos} minutos")
    print("==========================================")
