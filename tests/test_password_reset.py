"""WBS 4.2 - Recuperacion de contrasena con token de un solo uso (R11).

Que propiedad prueba cada bloque y que pasaria si se rompiera:

  - Un token sirve UNA vez. Si `used_at` no se marcara, el enlace del correo
    seguiria abriendo la cuenta despues de cambiar la contrasena: una
    credencial permanente guardada en la bandeja de entrada.
  - Un token expira. Sin vencimiento, un correo viejo sigue siendo una llave.
  - Se marca la fila CORRECTA. Con un solo usuario `user_id` y `token_id`
    valen 1 y marcar la fila equivocada pasa en verde (LL10, LL14), por eso aqui
    siempre hay dos usuarios.
  - Un token nuevo invalida los anteriores del MISMO usuario. Si al `DELETE`
    le faltara el `WHERE user_id`, pedir un enlace cancelaria los de todos.
  - La respuesta es identica exista o no el email. Cualquier diferencia
    --codigo, destino o HTML-- convierte /forgot-password en un verificador de
    cuentas. Un 500 cuenta como diferencia: por eso se compara el codigo.
  - El token no sale por la respuesta HTTP ni por el log de auditoria, y en la
    BD solo esta su SHA-256. Son las tres fugas posibles del secreto.
  - Consumir el token sube `session_version` y reinicia el contador de 4.1.
    Cambiar la contrasena sin cerrar las sesiones abiertas deja dentro a quien
    tenga una cookie robada, que es justo de quien se esta recuperando la cuenta.
  - La politica de contrasenas aplica en el reset igual que en el registro.
    `validar_password()` es compartida: un fail-open aqui la borra de los dos
    lados a la vez (LL11, LL12).

El token en claro solo existe en memoria y en la consola, asi que las pruebas
lo obtienen de una de dos formas: llamando a `issue_token()` directamente
(rapido y deterministico) o leyendo la consola con `capsys` cuando lo que se
prueba es el flujo completo de /forgot-password.
"""
import hashlib
import json
import re
import sqlite3
import time

import bcrypt
import pytest

from conftest import PASSWORD, USERNAME
from src.reset_tokens import issue_token

EMAIL = "ana@example.com"
BETO = "beto"
EMAIL_BETO = "beto@example.com"

NUEVA = "ContrasenaNueva456"
OTRA = "ContrasenaOtra789"

# Corta para que el token expire dentro de la prueba, pero holgada frente a los
# ~330 ms de bcrypt: una vida mas corta que la operacion que se mide haria que
# la prueba midiera otra cosa (LL10).
VIDA_CORTA = 2


# --- Ayudantes -------------------------------------------------------------

def crear_usuario(db, username, email, password=PASSWORD):
    """Inserta un usuario y devuelve su id (mismo trabajo que la fixture `usuario`)."""
    cur = db.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email,
         bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()),
    )
    db.commit()
    return cur.lastrowid


def conectar(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def entra_con(db, user_id, password):
    """True si `password` corresponde al hash guardado de ese usuario."""
    fila = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return bcrypt.checkpw(password.encode(), fila["password_hash"].encode())


def version_de(db, user_id):
    return db.execute(
        "SELECT session_version FROM users WHERE id = ?", (user_id,)
    ).fetchone()[0]


def tokens_de(db, user_id):
    """Las filas de password_reset_tokens de un usuario, de la mas vieja a la mas nueva."""
    return db.execute(
        "SELECT id, used_at FROM password_reset_tokens WHERE user_id = ? ORDER BY id",
        (user_id,),
    ).fetchall()


def intentos_de(db, username):
    return db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ?", (username,)
    ).fetchone()[0]


def usar(client, token, password=NUEVA):
    """POST /reset-password. Devuelve el destino de la redireccion."""
    return client.post(
        "/reset-password",
        data={"token": token, "password": password, "confirm_password": password},
    ).headers["Location"]


def token_de_la_consola(capsys):
    """Extrae el token del enlace que el mailer simulado imprime en la terminal.

    Es el unico lugar del que se puede sacar: a proposito no aparece ni en la
    respuesta HTTP ni en el log.
    """
    salida = capsys.readouterr().out
    for linea in salida.splitlines():
        if linea.startswith("Enlace: "):
            return linea.split("/reset-password/")[1].strip()
    raise AssertionError(f"El mailer no imprimio ningun enlace:\n{salida}")


def sin_csrf(html):
    """Borra el valor del token CSRF, que cambia por sesion y no compara nada.

    Se normaliza en lugar de ignorar la comparacion completa: todo lo demas del
    HTML si tiene que ser identico byte a byte.
    """
    return re.sub(r'name="csrf_token" value="[^"]*"', 'name="csrf_token"', html)


@pytest.fixture
def emitir(app, db):
    """Devuelve una funcion que emite un token en claro para un user_id."""
    def _emitir(user_id):
        with app.app_context():
            return issue_token(db, user_id)

    return _emitir


# --- Un solo uso y vencimiento (WBS 4.2.7) ---------------------------------

def test_un_token_solo_sirve_una_vez(client, db, usuario, emitir):
    """El segundo intento con el mismo enlace no debe cambiar nada.

    Se comprueba el efecto y no la respuesta: que la SEGUNDA contrasena no
    quedo guardada. Un reset que redirige a /login pero ya escribio en users
    se veria igual en el navegador.
    """
    token = emitir(usuario)

    assert usar(client, token, NUEVA).endswith("/login")
    assert entra_con(db, usuario, NUEVA)

    assert usar(client, token, OTRA).endswith("/forgot-password")
    assert entra_con(db, usuario, NUEVA), "el token usado cambio la contrasena otra vez"
    assert not entra_con(db, usuario, OTRA)


def test_un_token_expirado_es_rechazado(make_app):
    """La vida del token se lee de la config: aqui se baja a segundos.

    Monta su propia app porque las demas pruebas necesitan la vigencia normal;
    con VIDA_CORTA global, cualquier prueba que haga un login antes del reset
    veria expirar el token a media ejecucion por el costo de bcrypt.
    """
    app = make_app(RESET_TOKEN_LIFETIME_SECONDS=VIDA_CORTA)
    db = conectar(app)
    user_id = crear_usuario(db, USERNAME, EMAIL)

    with app.app_context():
        token = issue_token(db, user_id)

    time.sleep(VIDA_CORTA + 1)

    assert usar(app.test_client(), token).endswith("/forgot-password")
    assert entra_con(db, user_id, PASSWORD), "un token vencido cambio la contrasena"
    assert tokens_de(db, user_id)[0]["used_at"] is None
    db.close()


def test_un_token_inventado_es_rechazado(client, db, usuario, eventos):
    """Nunca existio, pero el camino de salida es el mismo que el de uno vencido."""
    assert usar(client, "token-que-nadie-emitio").endswith("/forgot-password")
    assert entra_con(db, usuario, PASSWORD)
    assert [e["event"] for e in eventos()] == ["password_reset_failure"]


def test_inexistente_y_usado_son_indistinguibles(app, client, db, usuario, emitir):
    """R11: los tres motivos de rechazo deben terminar exactamente igual.

    Si el token usado dijera "ya lo usaste" y el inventado "no existe", el
    formulario contestaria si un enlace fue emitido alguna vez.
    """
    token = emitir(usuario)
    usar(client, token)

    def rechazo(valor):
        c = app.test_client()
        r = c.post("/reset-password",
                   data={"token": valor, "password": OTRA, "confirm_password": OTRA})
        destino = r.headers["Location"]
        return r.status_code, destino, sin_csrf(c.get(destino).get_data(as_text=True))

    assert rechazo(token) == rechazo("token-que-nadie-emitio")


# --- La fila correcta, con dos usuarios (LL14) -----------------------------

def test_se_marca_la_fila_del_token_usado_y_no_otra(client, db, usuario, emitir):
    """Con un solo usuario este bug pasa en verde: user_id y token_id valen 1.

    Dos usuarios tampoco bastan por si solos: si ana emitiera primero, su token
    seria el id 1 igual que su user_id, y confundir una columna con la otra
    volveria a pasar en verde. Beto emite PRIMERO para desalinear los ids, de
    modo que el token que se usa (id 2) pertenezca al usuario 1.
    """
    beto = crear_usuario(db, BETO, EMAIL_BETO)
    emitir(beto)
    token_ana = emitir(usuario)

    (fila_ana,) = tokens_de(db, usuario)
    assert fila_ana["id"] != usuario, "los ids quedaron alineados: la prueba no probaria nada"

    assert usar(client, token_ana, NUEVA).endswith("/login")

    assert tokens_de(db, usuario)[0]["used_at"] is not None, "no se marco el token usado"
    assert tokens_de(db, beto)[0]["used_at"] is None, "se marco el token de otro usuario"

    assert entra_con(db, usuario, NUEVA)
    assert entra_con(db, beto, PASSWORD), "se cambio la contrasena del usuario equivocado"
    assert version_de(db, beto) == 0


def test_un_token_nuevo_invalida_solo_los_del_mismo_usuario(client, db, usuario, emitir):
    """El `WHERE user_id` del DELETE de issue_token().

    Sin el, pedir un enlace cancelaria los de todos los usuarios: un DoS de
    recuperacion disparado por cualquiera que conozca un solo email.
    """
    beto = crear_usuario(db, BETO, EMAIL_BETO)
    token_beto = emitir(beto)

    viejo = emitir(usuario)
    nuevo = emitir(usuario)

    assert len(tokens_de(db, usuario)) == 1, "el token viejo no se borro"
    assert len(tokens_de(db, beto)) == 1, "el token de otro usuario desaparecio"

    assert usar(client, viejo, OTRA).endswith("/forgot-password")
    assert entra_con(db, usuario, PASSWORD)

    assert usar(client, nuevo, NUEVA).endswith("/login")
    assert entra_con(db, usuario, NUEVA)

    assert usar(client, token_beto, OTRA).endswith("/login"), "el token de beto quedo invalidado"


# --- Sin enumeracion de cuentas (WBS 4.2.2) --------------------------------

def test_la_respuesta_es_identica_exista_o_no_el_email(app, db, usuario):
    """Codigo, destino y HTML: las tres cosas que un atacante puede comparar.

    El codigo se compara porque un 500 tambien es un oraculo: desempacar un
    fetchone() que devuelve None daba 302 si el email existia y 500 si no (LL15).
    Cada rama usa su propio cliente para que los mensajes flash no se mezclen.
    """
    def pedir(email):
        c = app.test_client()
        r = c.post("/forgot-password", data={"email": email})
        destino = r.headers["Location"]
        return r.status_code, destino, sin_csrf(c.get(destino).get_data(as_text=True))

    codigo_si, destino_si, html_si = pedir(EMAIL)
    codigo_no, destino_no, html_no = pedir("nadie@example.com")

    assert codigo_si == codigo_no == 302
    assert destino_si == destino_no
    assert html_si == html_no

    # Y sin embargo el token si se emitio en una de las dos ramas: la prueba
    # anterior no seria nada si ambas no hicieran nada.
    assert len(tokens_de(db, usuario)) == 1


def test_el_log_registra_la_solicitud_exista_o_no_el_email(client, db, usuario, eventos):
    """La respuesta es ciega, el log no: ahi si se distingue (y solo ahi)."""
    client.post("/forgot-password", data={"email": EMAIL})
    client.post("/forgot-password", data={"email": "nadie@example.com"})

    registrados = [e for e in eventos() if e["event"] == "password_reset_requested"]
    assert len(registrados) == 2
    assert registrados[0]["user_id"] == usuario
    assert registrados[1]["user_id"] is None


# --- El token no se filtra (WBS 4.2.3) -------------------------------------

def test_el_token_no_sale_por_la_respuesta_ni_por_el_log(client, db, usuario, eventos, capsys):
    """Las tres fugas posibles del secreto: la respuesta HTTP, el log y la BD."""
    respuesta = client.post("/forgot-password", data={"email": EMAIL},
                            follow_redirects=True).get_data(as_text=True)
    token = token_de_la_consola(capsys)

    assert token not in respuesta, "el enlace se filtro por la respuesta HTTP"

    log = "\n".join(json.dumps(e, ensure_ascii=False) for e in eventos())
    assert token not in log, "el enlace se filtro al log de auditoria"

    fila = db.execute("SELECT token_hash FROM password_reset_tokens").fetchone()
    assert fila["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in fila["token_hash"], "el token esta guardado en claro"

    # El token de la consola es el que abre la cuenta: si no, esta prueba
    # estaria comparando contra una cadena que no es el secreto real.
    assert usar(client, token, NUEVA).endswith("/login")
    assert entra_con(db, usuario, NUEVA)


def test_el_formulario_del_token_no_audita(client, db, usuario, emitir, eventos):
    """WBS 4.2.5: hay dos rutas y no una justamente por esto.

    En el GET el token viaja en request.path, y audit() guarda el path. Un solo
    audit() en esa vista escribiria el token en claro en el archivo de auditoria.
    """
    token = emitir(usuario)

    antes = len(eventos())
    html = client.get(f"/reset-password/{token}").get_data(as_text=True)

    assert eventos()[antes:] == [], "el GET con el token en la URL escribio en el log"
    assert f'name="token" value="{token}"' in html


# --- Consumir el token cierra sesiones y reinicia el contador (WBS 4.2.6) ---

def test_el_reset_cierra_las_sesiones_abiertas_y_reinicia_el_contador(app, client, db, usuario, emitir):
    """R9 + R10 desde el flujo de recuperacion.

    Quien recupera su cuenta suele hacerlo porque alguien mas tiene la cookie:
    cambiar la contrasena sin invalidar las sesiones abiertas no lo saca. Y el
    contador de 4.1 tiene que volver a cero o la cuenta recien recuperada queda
    bloqueada por los intentos del atacante.
    """
    navegador = app.test_client()
    navegador.post("/login", data={"username": USERNAME, "password": PASSWORD})
    assert navegador.get("/dashboard").status_code == 200

    for _ in range(3):
        client.post("/login", data={"username": USERNAME, "password": "incorrecta"})
    assert intentos_de(db, USERNAME) == 3

    version_antes = version_de(db, usuario)
    assert usar(client, emitir(usuario), NUEVA).endswith("/login")

    assert version_de(db, usuario) == version_antes + 1
    assert intentos_de(db, USERNAME) == 0
    assert navegador.get("/dashboard").headers["Location"].endswith("/login"), \
        "la sesion abierta sobrevivio al cambio de contrasena"

    # Y la cuenta funciona con la contrasena nueva, no solo quedo rota.
    limpio = app.test_client()
    destino = limpio.post("/login", data={"username": USERNAME, "password": NUEVA})
    assert destino.headers["Location"].endswith("/dashboard")


# --- Politica de contrasenas compartida (LL11, LL12) -----------------------

def test_el_reset_rechaza_una_contrasena_corta_sin_consumir_el_token(client, db, usuario, emitir):
    """Un rechazo no puede quemar el enlace: seria un DoS contra quien se equivoca."""
    token = emitir(usuario)

    destino = client.post(
        "/reset-password",
        data={"token": token, "password": "abc", "confirm_password": "abc"},
    ).headers["Location"]

    assert destino.endswith(f"/reset-password/{token}")
    assert entra_con(db, usuario, PASSWORD), "se acepto una contrasena de 3 caracteres"
    assert tokens_de(db, usuario)[0]["used_at"] is None, "un rechazo consumio el token"

    assert usar(client, token, NUEVA).endswith("/login")


def test_el_reset_exige_que_la_confirmacion_coincida(client, db, usuario, emitir):
    token = emitir(usuario)

    client.post("/reset-password",
                data={"token": token, "password": NUEVA, "confirm_password": OTRA})

    assert entra_con(db, usuario, PASSWORD)
    assert not entra_con(db, usuario, NUEVA)


def test_register_rechaza_una_contrasena_corta(client, db):
    """Los dos asserts que habrian atrapado el fail-open de esta sesion.

    `validar_password()` devolvia None en el camino bueno y `register()` no
    retornaba su redirect: la politica de contrasenas dejo de existir sin que
    nada fallara. Un fail-closed se reporta en cinco minutos; un fail-open no
    se nota nunca (LL11, LL12).
    """
    destino = client.post("/register", data={
        "username": "nuevo", "email": "nuevo@example.com",
        "password": "abc", "confirm_password": "abc",
    }).headers["Location"]

    assert destino.endswith("/register")
    assert db.execute(
        "SELECT COUNT(*) FROM users WHERE username = ?", ("nuevo",)
    ).fetchone()[0] == 0, "se creo una cuenta con una contrasena de 3 caracteres"
