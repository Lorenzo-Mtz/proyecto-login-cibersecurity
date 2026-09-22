"""WBS 4.5.4 - Caducidad de la sesion (R9).

Archivo aparte de test_session.py: aquel cubre 4.5.2, la invalidacion
server-side por session_version. Aqui se prueban DOS controles distintos que
conviven y que es facil confundir:

  - Inactividad (PERMANENT_SESSION_LIFETIME): cuenta desde la ultima peticion,
    lo aplica Flask solo y se DESLIZA con el uso.
  - Vida maxima (SESSION_ABSOLUTE_LIFETIME_SECONDS): cuenta desde el login, se
    comprueba en @login_required y la actividad NO la renueva.

Que se prueba y por que cada cosa:

  - El tope absoluto rechaza la sesion vieja, y el rechazo se AUDITA. Aseverar
    sobre el evento y no solo sobre el redirect es lo que separa esta prueba de
    un falso verde: una sesion rechazada por session_version tambien redirige
    al login, y entonces no se estaria probando nada de 4.5.4.
  - Justo por debajo del tope la sesion sigue viva: sin esto, un control que
    rechazara SIEMPRE pasaria la prueba anterior.
  - Una sesion sin login_at se rechaza (fail-closed). Cubre las cookies
    emitidas antes de 4.5.4 y cualquier punto futuro que abra sesion y olvide
    poner la marca.
  - LA PRUEBA DEL PAQUETE: usar la sesion sin parar NO estira el tope. Es la
    unica que distingue el control absoluto del de inactividad; sin ella, las
    demas pasarian igual aunque el tope se renovara en cada peticion, que es
    justo el defecto que 4.5.4 vino a corregir.
  - La inactividad tambien cierra la sesion, y NO deja rastro en el log. Eso
    ultimo es una limitacion inherente, no un olvido: Flask descarta la cookie
    vencida antes de llegar a la vista y la sesion entra vacia, sin user_id que
    anotar. Queda como prueba para que, si algun dia cambia, salte.

Ojo con los tiempos (LL10): cada login cuesta ~330 ms por bcrypt, asi que los
umbrales cortos de aqui llevan holgura a proposito.
"""
import json
import time
from datetime import timedelta

from src.audit import audit_logger
from conftest import PASSWORD, USERNAME

# Corto para que las pruebas no tarden, holgado frente al costo de bcrypt.
VIDA_CORTA = 3
INACTIVIDAD_CORTA = 2


def entrar(client):
    return client.post("/login", data={"username": USERNAME, "password": PASSWORD})


def envejecer(client, segundos):
    """Retrasa login_at: es lo mismo que esperar, sin esperar.

    El cliente real no puede hacer esto -- la firma se lo impide -- pero la
    prueba habla con la sesion por dentro, antes de firmarla.
    """
    with client.session_transaction() as sesion:
        sesion["login_at"] = int(time.time()) - segundos


def eventos_de(app):
    """Lee el log de una app montada a mano con make_app."""
    for handler in audit_logger.handlers:
        handler.flush()
    with open(app.config["AUDIT_LOG"], encoding="utf-8") as f:
        return [json.loads(linea)["event"] for linea in f if linea.strip()]


def test_una_sesion_mas_vieja_que_el_tope_es_rechazada(app, client, usuario, eventos):
    entrar(client)
    assert client.get("/dashboard").status_code == 200

    envejecer(client, app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"] + 1)

    assert client.get("/dashboard").headers["Location"].endswith("/login")

    nombres = [e["event"] for e in eventos()]
    assert "session_expired" in nombres
    # El guard del falso verde: si entrara por aqui, el redirect de arriba
    # estaria probando la invalidacion de 4.5.2 y no el tope de 4.5.4.
    assert "session_rejected" not in nombres


def test_una_sesion_dentro_del_tope_sigue_viva(app, client, usuario):
    """Sin esto, un control que rechazara siempre pasaria la prueba anterior."""
    entrar(client)

    envejecer(client, app.config["SESSION_ABSOLUTE_LIFETIME_SECONDS"] - 60)

    assert client.get("/dashboard").status_code == 200


def test_una_sesion_sin_login_at_es_rechazada(client, usuario, eventos):
    """Fail-closed: sin marca no hay forma de saber si vencio, asi que vence."""
    entrar(client)
    with client.session_transaction() as sesion:
        del sesion["login_at"]

    assert client.get("/dashboard").headers["Location"].endswith("/login")
    assert "session_expired" in [e["event"] for e in eventos()]


def test_la_actividad_no_renueva_el_tope(make_app, db, usuario):
    """La prueba del paquete: el tope absoluto no se estira usandolo.

    Se golpea una ruta protegida sin parar mientras el tope corre. Si se
    renovara en cada peticion -- como hace el de inactividad -- esta sesion no
    expiraria jamas y el bucle se agotaria por tiempo.
    """
    app = make_app(SESSION_ABSOLUTE_LIFETIME_SECONDS=VIDA_CORTA)
    client = app.test_client()
    entrar(client)

    expiro = False
    usos = 0
    inicio = time.time()
    while time.time() - inicio < VIDA_CORTA * 3:
        if client.get("/dashboard").status_code != 200:
            expiro = True
            break
        usos += 1
        time.sleep(0.3)

    assert expiro, "el tope absoluto se renovo con el uso"
    # Sin esto, una sesion que muriera al primer intento tambien pasaria: se
    # estaria midiendo cualquier cosa menos el uso continuado.
    assert usos >= 3, f"la sesion solo se uso {usos} veces; la prueba no prueba nada"


def test_la_inactividad_cierra_la_sesion(make_app, db, usuario):
    """El otro control, el que aplica Flask solo: aqui solo se verifica."""
    app = make_app(PERMANENT_SESSION_LIFETIME=timedelta(seconds=INACTIVIDAD_CORTA))
    client = app.test_client()
    entrar(client)
    assert client.get("/dashboard").status_code == 200

    time.sleep(INACTIVIDAD_CORTA + 1)

    assert client.get("/dashboard").headers["Location"].endswith("/login")


def test_la_inactividad_no_deja_rastro_en_el_log(make_app, db, usuario):
    """Limitacion documentada, no olvido.

    Flask descarta la cookie vencida en open_session y la sesion llega vacia:
    @login_required ve una peticion sin user_id, indistinguible de alguien que
    nunca inicio sesion. No hay a quien atribuir el evento. Si algun dia esto
    cambia, hay que actualizar el comentario de session_expired en audit.py.
    """
    app = make_app(PERMANENT_SESSION_LIFETIME=timedelta(seconds=INACTIVIDAD_CORTA))
    client = app.test_client()
    entrar(client)

    time.sleep(INACTIVIDAD_CORTA + 1)
    client.get("/dashboard")

    assert "session_expired" not in eventos_de(app)
