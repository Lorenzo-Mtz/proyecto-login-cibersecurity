"""Segundo factor por TOTP (WBS 4.3, R4 y R12).

El algoritmo lo implementa pyotp (RFC 6238); este modulo no lo reimplementa,
que es justo el error que R4 anticipa. Lo que si vive aqui es todo lo que
pyotp NO decide por ti, que es donde estan los agujeros reales de un MFA:
cuantos periodos se toleran, que un codigo usado no vuelva a servir, y que un
codigo mal formado no tumbe la peticion.

Modulo aparte y no dentro de auth.py por la misma razon que throttle.py: lo
que no es ruteo se puede probar sin levantar un servidor ni pagar los ~330 ms
de bcrypt de un login.
"""
import base64
import io
import time
from hmac import compare_digest

import pyotp
import qrcode
import qrcode.image.svg
from flask import current_app

# Longitud del codigo que genera una app autenticadora estandar.
CODE_LENGTH = 6


def _totp(secret):
    """Construye el TOTP con el periodo de la configuracion.

    pyotp usa 30 por default, que es el mismo valor, pero leerlo de la config
    evita que el default de la libreria y TOTP_PERIOD puedan discrepar sin que
    nadie se entere.
    """
    return pyotp.TOTP(secret, interval=current_app.config["TOTP_PERIOD"])


def generar_secreto():
    """Devuelve un secreto compartido nuevo, en base32.

    Base32 porque es lo que entienden las apps autenticadoras. pyotp usa el
    modulo secrets por debajo: 160 bits de un CSPRNG, que es lo que recomienda
    el RFC 4226 para la semilla.
    """
    return pyotp.random_base32()


def uri_de_aprovisionamiento(secret, username):
    """Arma la URI otpauth:// que se codifica en el QR.

    Queda algo asi (OJO: el secreto va ahi dentro, en claro -- esta URI ES la
    credencial, no una referencia a ella):

        otpauth://totp/Login%20Seguro:ana?secret=IH7R...&issuer=Login%20Seguro

    El issuer sale de la configuracion y no de una constante aqui: es lo que la
    app autenticadora muestra como nombre del servicio, y no deberia hacer
    falta tocar codigo para cambiarlo.
    """
    return _totp(secret).provisioning_uri(
        name=username, issuer_name=current_app.config["MFA_ISSUER"]
    )


def qr_data_uri(uri):
    """Convierte la URI en un data: URI listo para el atributo src de un <img>.

    Devuelve la cadena completa, con prefijo:

        data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0...

    SVG y no PNG: el PNG exige Pillow (ver requirements.txt). Embebido y no
    servido desde una ruta propia: esa ruta seria una URL que entrega el
    secreto compartido y necesitaria su propio control de acceso.
    """
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, border=2)
    buffer = io.BytesIO()
    img.save(buffer)
    b64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def verificar_codigo(secret, codigo, ultimo_timecode=None, ahora=None):
    """Valida un codigo TOTP. Devuelve el NUMERO DE PERIODO aceptado, o None.

    Devuelve el periodo y no un booleano a proposito: quien llama tiene que
    guardarlo para rechazar la reutilizacion. Con un bool no tendria que
    guardar, y el control de replay no podria existir.

    `ultimo_timecode` es el periodo del ultimo codigo que este usuario uso con
    exito. Solo se aceptan periodos ESTRICTAMENTE MAYORES, lo que de un golpe
    rechaza el codigo repetido y tambien los anteriores de la ventana: quien
    haya visto un codigo por encima del hombro no puede usarlo aunque le
    queden segundos de vida.

    `ahora` es inyectable para que las pruebas puedan pararse en un instante
    concreto en vez de esperar a que cambie el periodo (LL10).
    """
    periodo = current_app.config["TOTP_PERIOD"]
    ventana = current_app.config["TOTP_VALID_WINDOW"]
    ahora = int(time.time() if ahora is None else ahora)

    # Las apps autenticadoras muestran el codigo como "123 456" y la gente lo
    # copia con el espacio.
    codigo = "".join(codigo.split())

    # Este filtro va ANTES de comparar y no es cosmetico: compare_digest lanza
    # TypeError con cualquier cosa que no sea ASCII, y esa excepcion terminaria
    # en un 500. Un 500 es una respuesta distinta a "codigo incorrecto", o sea
    # un oraculo (LL15).
    #
    # isdigit() no basta por si solo: es True para los digitos arabigo-indicos
    # ('١٢٣'), que son digitos y no son ASCII.
    if len(codigo) != CODE_LENGTH or not (codigo.isascii() and codigo.isdigit()):
        return None

    totp = _totp(secret)

    for offset in range(-ventana, ventana + 1):
        instante = ahora + offset * periodo
        timecode = instante // periodo

        # El descarte va ANTES de comparar, no despues. Si fuera despues, un
        # codigo ya usado entraria al compare_digest y solo se rechazaria por
        # el periodo -- mismo resultado, pero habriamos confirmado que el
        # codigo era correcto antes de decidir. Descartar primero no le da a
        # nadie la oportunidad de medir esa diferencia.
        if ultimo_timecode is not None and timecode <= ultimo_timecode:
            continue

        # compare_digest y no ==: comparar cadenas con == termina en cuanto
        # encuentra el primer caracter distinto, asi que el tiempo de respuesta
        # dice cuantos digitos se acertaron. Con eso, adivinar seis digitos
        # deja de ser un millon de intentos y pasa a ser sesenta.
        if compare_digest(totp.at(instante), codigo):
            return timecode

    return None
