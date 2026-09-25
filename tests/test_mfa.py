"""WBS 4.3 - Segundo factor por TOTP (R4, R12).

Que propiedad prueba cada bloque y que pasaria si se rompiera:

  - La tolerancia es de EXACTAMENTE +-1 periodo. Cada periodo extra triplica
    los codigos validos en un instante dado, y ampliarla no se ve distinto
    desde el navegador.
  - Un codigo usado no vuelve a servir, y tampoco los anteriores de la
    ventana. Sin eso, quien vea un codigo por encima del hombro tiene hasta 90
    segundos para usarlo, y el segundo factor pasa a ser "algo que alguien
    vio" en vez de "algo que tienes".
  - Un codigo mal formado devuelve None, no una excepcion. compare_digest
    lanza TypeError con lo que no sea ASCII, y un 500 en un flujo de
    autenticacion es una respuesta distinta a "codigo incorrecto" (LL15).
  - MFA no se activa hasta validar un primer codigo. Activarlo al mostrar el
    QR deja fuera de su cuenta a quien cierre la pestana sin escanear, y sin
    codigos de respaldo (R13) la unica salida es editar la BD a mano.
  - La contrasena sola no abre sesion. La sesion pendiente no lleva user_id,
    asi que @login_required la rechaza sin codigo de autorizacion nuevo.
  - La contrasena correcta NO reinicia el contador de 4.1 cuando hay MFA. Si
    lo reiniciara, quien tenga la contrasena podria probar codigos de cinco en
    cinco volviendo a loguearse, y el limite del segundo factor seria adorno.
  - Un intento bloqueado se audita pero no se cuenta: contarlo dejaria
    mantener la cuenta bloqueada para siempre con una peticion cada quince
    minutos (R10). El contador decide, el log narra.
  - El secreto TOTP no sale por la cookie de sesion ni por el log. La cookie
    de Flask va FIRMADA, no cifrada: lo que se guarde ahi es legible.

HUECO CONOCIDO: sustituir hmac.compare_digest por == en mfa.py no lo atrapa
ninguna prueba de este archivo. Medir una diferencia de microsegundos sobre
seis digitos dentro del mismo proceso no da una senal estable, a diferencia de
los ~330 ms de bcrypt que si permiten test_sin_oraculo_por_latencia en 4.1.
Ese control se sostiene por revision de codigo, no por prueba.

El reloj se inyecta (`ahora=`) en las pruebas del modulo, para no esperar 30
segundos a que cambie el periodo (LL10).
"""
import json
import time

import pyotp
import pytest

from conftest import PASSWORD, USERNAME
from src.mfa import verificar_codigo

# Multiplo exacto de 30: el periodo empieza justo aqui, asi que no hay bordes
# ambiguos al sumar o restar un periodo.
AHORA = 1_700_000_000
PERIODO_DE_AHORA = AHORA // 30


# --- Ayudantes -------------------------------------------------------------

def activar_mfa(db, user_id, secret=None):
    """Deja la cuenta con MFA activo sin pasar por el enrolamiento.

    Las pruebas del login no deben depender de que el enrolamiento funcione:
    si ambos se rompieran a la vez, un solo fallo taparia al otro.
    """
    secret = secret or pyotp.random_base32()
    db.execute(
        "UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?",
        (secret, user_id),
    )
    db.commit()
    return secret


def codigo_actual(secret):
    return pyotp.TOTP(secret).now()


def entrar_con_password(client):
    return client.post(
        "/login", data={"username": USERNAME, "password": PASSWORD}
    ).headers["Location"]


def enviar_codigo(client, codigo, ruta="/mfa"):
    """POST del formulario del codigo. Devuelve el destino de la redireccion."""
    return client.post(ruta, data={"codigo": codigo}).headers["Location"]


def estado(db, user_id):
    return db.execute(
        "SELECT mfa_enabled, totp_secret, last_mfa_timecode FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def intentos_de(db, username):
    return db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ?", (username,)
    ).fetchone()[0]


# --- verificar_codigo: ventana y reutilizacion (WBS 4.3.5) -----------------

def test_acepta_el_codigo_del_periodo_actual(app):
    secret = pyotp.random_base32()
    with app.app_context():
        aceptado = verificar_codigo(secret, pyotp.TOTP(secret).at(AHORA), ahora=AHORA)
    assert aceptado == PERIODO_DE_AHORA, "devuelve el periodo, no un booleano"


def test_la_tolerancia_es_de_exactamente_un_periodo(app):
    """+-1 sirve, +-2 no. Un rango de mas ampliaria la ventana en silencio."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    with app.app_context():
        def prueba(offset):
            return verificar_codigo(secret, totp.at(AHORA + offset * 30), ahora=AHORA)

        assert prueba(-1) == PERIODO_DE_AHORA - 1, "el codigo anterior debe servir"
        assert prueba(1) == PERIODO_DE_AHORA + 1, "el codigo siguiente debe servir"
        assert prueba(-2) is None, "dos periodos atras NO debe servir"
        assert prueba(2) is None, "dos periodos adelante NO debe servir"


def test_un_codigo_usado_no_vuelve_a_servir(app):
    """El replay se rechaza comparando periodos, no guardando el codigo."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    with app.app_context():
        usado = verificar_codigo(secret, totp.at(AHORA), ahora=AHORA)
        assert usado == PERIODO_DE_AHORA

        assert verificar_codigo(secret, totp.at(AHORA), usado, ahora=AHORA) is None, \
            "el mismo codigo se acepto dos veces"


def test_un_codigo_usado_invalida_tambien_los_anteriores_de_la_ventana(app):
    """Exigir un periodo MAYOR, y no solo distinto, cierra la ventana hacia atras.

    Si solo se rechazara el codigo repetido, el del periodo anterior seguiria
    siendo valido y quien lo haya visto tendria 30 segundos para usarlo.
    """
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    with app.app_context():
        usado = verificar_codigo(secret, totp.at(AHORA), ahora=AHORA)

        assert verificar_codigo(secret, totp.at(AHORA - 30), usado, ahora=AHORA) is None
        # El siguiente si, o el usuario tendria que esperar sin motivo.
        assert verificar_codigo(secret, totp.at(AHORA + 30), usado, ahora=AHORA) \
            == PERIODO_DE_AHORA + 1


@pytest.mark.parametrize("basura", [
    "",
    "   ",
    "abcdef",
    "12345",        # cinco digitos
    "1234567",      # siete
    "١٢٣٤٥٦",  # arabigo-indicos: isdigit() es True, ASCII no
    "12 34 5",
])
def test_un_codigo_mal_formado_devuelve_none_y_no_revienta(app, basura):
    """Sin el filtro previo, esto termina en 500 -- que es un oraculo (LL15)."""
    secret = pyotp.random_base32()
    with app.app_context():
        assert verificar_codigo(secret, basura, ahora=AHORA) is None


def test_el_espacio_de_la_app_autenticadora_no_estorba(app):
    """Google Authenticator muestra "123 456" y la gente lo copia con el espacio."""
    secret = pyotp.random_base32()
    codigo = pyotp.TOTP(secret).at(AHORA)

    with app.app_context():
        assert verificar_codigo(secret, f"{codigo[:3]} {codigo[3:]}", ahora=AHORA) \
            == PERIODO_DE_AHORA


# --- Enrolamiento (WBS 4.3.3) ----------------------------------------------

def test_el_enrolamiento_exige_sesion(client):
    """El QR ES el secreto: la pagina que lo muestra no puede ser publica."""
    assert client.get("/mfa/setup").headers["Location"].endswith("/login")
    assert client.post("/mfa/setup", data={"codigo": "000000"}) \
        .headers["Location"].endswith("/login")


def test_mfa_no_se_activa_hasta_validar_un_codigo(client, db, usuario):
    """La regla del paquete. Activar al mostrar el QR deja gente fuera de su cuenta."""
    entrar_con_password(client)

    assert client.get("/mfa/setup").status_code == 200
    fila = estado(db, usuario)
    assert fila["totp_secret"] is not None, "el secreto no se guardo"
    assert fila["mfa_enabled"] == 0, "MFA se activo con solo abrir la pagina"

    # Un codigo incorrecto tampoco lo activa.
    assert enviar_codigo(client, "000000", "/mfa/setup").endswith("/mfa/setup")
    assert estado(db, usuario)["mfa_enabled"] == 0

    secret = fila["totp_secret"]
    assert enviar_codigo(client, codigo_actual(secret), "/mfa/setup").endswith("/dashboard")
    assert estado(db, usuario)["mfa_enabled"] == 1


def test_el_secreto_no_cambia_al_recargar_el_formulario(client, db, usuario):
    """Si cambiara, el QR ya escaneado dejaria de coincidir con el telefono."""
    entrar_con_password(client)

    client.get("/mfa/setup")
    primero = estado(db, usuario)["totp_secret"]
    client.get("/mfa/setup")
    client.get("/mfa/setup")

    assert estado(db, usuario)["totp_secret"] == primero


def test_el_codigo_del_enrolamiento_queda_consumido(client, db, usuario):
    """Si no se guardara su periodo, ese mismo codigo abriria el primer login."""
    entrar_con_password(client)
    client.get("/mfa/setup")
    secret = estado(db, usuario)["totp_secret"]

    codigo = codigo_actual(secret)
    enviar_codigo(client, codigo, "/mfa/setup")
    assert estado(db, usuario)["last_mfa_timecode"] is not None, \
        "el codigo del enrolamiento no quedo registrado"

    client.post("/logout")
    entrar_con_password(client)
    assert enviar_codigo(client, codigo).endswith("/mfa"), \
        "el codigo del enrolamiento sirvio para iniciar sesion"


def test_el_secreto_no_viaja_en_la_cookie_de_sesion(client, db, usuario):
    """La cookie de Flask va FIRMADA, no cifrada: su contenido es legible.

    Guardar ahi el secreto durante el enrolamiento -que es la opcion comoda,
    porque todavia no esta confirmado- publicaria el segundo factor completo a
    cualquiera que tenga la cookie.
    """
    entrar_con_password(client)
    client.get("/mfa/setup")
    secret = estado(db, usuario)["totp_secret"]

    with client.session_transaction() as sesion:
        assert all(secret not in str(v) for v in sesion.values())

    # El nombre se lee de la config y no se escribe a mano: desde 6.2 lleva el
    # prefijo __Host- (gap G2), y una prueba que lo fije se romperia otra vez.
    galleta = client.get_cookie(client.application.config["SESSION_COOKIE_NAME"])
    assert galleta is not None
    assert secret not in galleta.decoded_value


def test_el_secreto_no_aparece_en_el_log(client, db, usuario, eventos):
    """R14: el secreto TOTP esta en la lista de lo que nunca se registra (4.4.3)."""
    entrar_con_password(client)
    client.get("/mfa/setup")
    secret = estado(db, usuario)["totp_secret"]
    codigo = codigo_actual(secret)
    enviar_codigo(client, codigo, "/mfa/setup")

    log = "\n".join(json.dumps(e, ensure_ascii=False) for e in eventos())
    assert secret not in log
    assert codigo not in log
    assert "mfa_activated" in log


# --- Login en dos pasos (WBS 4.3.4) ----------------------------------------

def test_la_contrasena_sola_no_da_acceso(client, db, usuario):
    """Lo que hace que el segundo factor sea un factor y no un adorno."""
    activar_mfa(db, usuario)

    assert entrar_con_password(client).endswith("/mfa")
    assert client.get("/dashboard").headers["Location"].endswith("/login")

    with client.session_transaction() as sesion:
        assert "user_id" not in sesion, "la sesion pendiente trae user_id"
        assert sesion["pending_mfa_user_id"] == usuario


def test_sin_sesion_pendiente_no_hay_formulario_de_codigo(client, db, usuario):
    activar_mfa(db, usuario)

    assert client.get("/mfa").headers["Location"].endswith("/login")
    assert enviar_codigo(client, "000000").endswith("/login")


def test_la_sesion_pendiente_caduca(make_app, db, usuario):
    """Una contrasena ya validada esperando el segundo factor no puede vivir dias."""
    app = make_app(MFA_PENDING_LIFETIME_SECONDS=1)
    client = app.test_client()
    activar_mfa(db, usuario)

    assert entrar_con_password(client).endswith("/mfa")
    time.sleep(2)

    assert client.get("/mfa").headers["Location"].endswith("/login")
    with client.session_transaction() as sesion:
        assert "pending_mfa_user_id" not in sesion


def test_el_login_completo_con_mfa_abre_sesion(client, db, usuario):
    secret = activar_mfa(db, usuario)

    entrar_con_password(client)
    assert enviar_codigo(client, codigo_actual(secret)).endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200
    assert estado(db, usuario)["last_mfa_timecode"] is not None


def test_un_codigo_usado_no_abre_una_segunda_sesion(app, db, usuario):
    """La reutilizacion, ahora sobre el flujo HTTP y no sobre la funcion suelta."""
    secret = activar_mfa(db, usuario)

    primero = app.test_client()
    entrar_con_password(primero)
    codigo = codigo_actual(secret)
    assert enviar_codigo(primero, codigo).endswith("/dashboard")

    segundo = app.test_client()
    entrar_con_password(segundo)
    assert enviar_codigo(segundo, codigo).endswith("/mfa"), "el codigo sirvio dos veces"
    assert segundo.get("/dashboard").headers["Location"].endswith("/login")


# --- Limite de intentos, reutilizando 4.1 (WBS 4.3.5) ----------------------

def test_la_contrasena_correcta_no_reinicia_el_contador_si_hay_mfa(client, db, usuario):
    """La decision menos evidente del paquete.

    Si acertar la contrasena borrara los fallos, quien la tenga podria probar
    codigos de cinco en cinco -volviendo a loguearse entre tanda y tanda- y el
    limite de intentos del segundo factor seria decorativo.
    """
    secret = activar_mfa(db, usuario)

    for _ in range(3):
        client.post("/login", data={"username": USERNAME, "password": "incorrecta"})
    assert intentos_de(db, USERNAME) == 3

    entrar_con_password(client)
    assert intentos_de(db, USERNAME) == 3, "la contrasena correcta borro los fallos"

    # Y cuando el segundo factor pasa, entonces si.
    enviar_codigo(client, codigo_actual(secret))
    assert intentos_de(db, USERNAME) == 0


def test_el_limite_de_intentos_aplica_a_los_codigos(app, client, db, usuario):
    """Sin esto, seis digitos son un millon de intentos gratis por periodo.

    Se comprueba ademas que el bloqueo le gana a un codigo VALIDO, igual que en
    4.1 le gana a la contrasena correcta: el guard va antes de verificar.
    """
    secret = activar_mfa(db, usuario)
    maximo = app.config["LOGIN_MAX_ATTEMPTS"]

    entrar_con_password(client)
    for _ in range(maximo):
        enviar_codigo(client, "000000")
    assert intentos_de(db, USERNAME) == maximo

    valido = codigo_actual(secret)
    assert enviar_codigo(client, valido).endswith("/mfa"), \
        "un codigo valido entro estando bloqueado"
    assert client.get("/dashboard").headers["Location"].endswith("/login")

    # El mismo codigo, sin el bloqueo, si entra: confirma que lo rechazado fue
    # el bloqueo y no el codigo.
    db.execute("DELETE FROM login_attempts WHERE username = ?", (USERNAME,))
    db.commit()
    assert enviar_codigo(client, valido).endswith("/dashboard")


def test_un_intento_bloqueado_no_prolonga_el_bloqueo(app, client, db, usuario):
    """R10: si contara, cualquiera con la contrasena bloquea la cuenta a voluntad.

    Se compara MAX(id) y no COUNT(*): si se insertara una fila y la limpieza de
    record_failed_attempt borrara una vieja, el conteo no cambiaria y el bug
    pasaria desapercibido (LL10).
    """
    activar_mfa(db, usuario)
    maximo = app.config["LOGIN_MAX_ATTEMPTS"]

    entrar_con_password(client)
    for _ in range(maximo):
        enviar_codigo(client, "000000")

    sql = "SELECT MAX(id) FROM login_attempts WHERE username = ?"
    antes = db.execute(sql, (USERNAME,)).fetchone()[0]

    for _ in range(3):
        enviar_codigo(client, "000000")

    assert db.execute(sql, (USERNAME,)).fetchone()[0] == antes


def test_el_intento_bloqueado_si_se_audita(app, client, db, usuario, eventos):
    """El contador decide, el log narra.

    Que no se cuente no significa que no se registre: un login_blocked en /mfa
    dice que alguien YA tiene la contrasena y lleva rato contra el segundo
    factor. Es de las lineas mas valiosas del archivo.
    """
    activar_mfa(db, usuario)
    maximo = app.config["LOGIN_MAX_ATTEMPTS"]

    entrar_con_password(client)
    for _ in range(maximo + 2):
        enviar_codigo(client, "000000")

    tipos = [e["event"] for e in eventos()]
    assert tipos.count("mfa_failure") == maximo
    assert tipos.count("login_blocked") == 2
    assert [e["path"] for e in eventos() if e["event"] == "login_blocked"] == ["/mfa"] * 2


def test_los_eventos_de_mfa_son_propios(client, db, usuario, eventos):
    """Mezclar un codigo fallido con login_failure borraria la senal.

    Un mfa_failure significa que alguien YA tiene la contrasena: es una alerta
    de otro nivel que un login fallido cualquiera. Y el exito se registra como
    login_success -- el mismo evento que el camino sin MFA-- porque en los dos
    significa lo mismo: se creo una sesion.
    """
    secret = activar_mfa(db, usuario)

    entrar_con_password(client)
    enviar_codigo(client, "000000")
    enviar_codigo(client, "000000")
    enviar_codigo(client, codigo_actual(secret))

    tipos = [e["event"] for e in eventos()]
    assert tipos == ["mfa_required", "mfa_failure", "mfa_failure", "login_success"]
