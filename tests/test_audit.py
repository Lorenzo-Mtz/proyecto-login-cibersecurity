"""WBS 4.4 - Registro de auditoria (R14).

Que se prueba y por que cada cosa:

  - Cada evento deja UNA linea JSON con los seis campos del formato.
  - El catalogo es cerrado: un evento no catalogado lanza ValueError en vez de
    escribirse. Si no, cualquier typo crearia un evento nuevo en silencio.
  - Log injection: un username con saltos de linea no puede fabricar una
    segunda linea que simule un evento falso. Es el corazon de R14.
  - Los secretos no llegan al log: la firma de audit() no acepta campos libres,
    asi que no hay forma de pasarle una contrasena por accidente.
  - La IP sale de remote_addr y nunca de X-Forwarded-For, que lo escribe el
    cliente y por tanto puede mentir.
  - Las rutas emiten el evento correcto en cada camino.
"""
import json

import pytest

from conftest import PASSWORD, USERNAME, token_csrf
from src.audit import EVENTS, MAX_FIELD_LENGTH, audit


def test_cada_evento_del_catalogo_deja_una_linea(app, eventos):
    """WBS 4.4.4: los 8 eventos catalogados se escriben."""
    with app.test_request_context("/ruta-de-prueba"):
        for nombre in EVENTS:
            audit(nombre, user_id=1, username="ana")

    registrados = [e["event"] for e in eventos()]
    assert registrados == list(EVENTS)


def test_el_formato_tiene_los_seis_campos(app, eventos):
    with app.test_request_context("/login"):
        audit("login_success", user_id=7, username="ana")

    registro = eventos()[0]
    assert set(registro) == {"ts", "event", "user_id", "username", "ip", "path"}
    assert registro["ts"].endswith("+00:00"), "el timestamp debe ser UTC explicito"
    assert registro["user_id"] == 7
    assert registro["path"] == "/login"


def test_un_evento_fuera_del_catalogo_es_un_error(app, eventos):
    """El catalogo cerrado convierte un typo en excepcion, no en un evento nuevo."""
    with app.test_request_context("/"):
        with pytest.raises(ValueError):
            audit("login_sucess")  # typo deliberado

    assert eventos() == []


def test_log_injection_un_username_no_puede_fabricar_una_linea(app, eventos):
    """R14: json.dumps escapa los saltos de linea.

    Sin ese escape, este username produciria dos lineas y la segunda se leeria
    como un login_success que nunca ocurrio.
    """
    malicioso = 'ana"}\n{"event": "login_success", "user_id": 1}'

    with app.test_request_context("/login"):
        audit("login_failure", username=malicioso)

    registros = eventos()
    assert len(registros) == 1, "el username fabrico una segunda linea"
    assert registros[0]["event"] == "login_failure"


def test_el_username_se_recorta(app, eventos):
    """Un campo sin limite deja que un atacante infle el log a voluntad."""
    with app.test_request_context("/login"):
        audit("login_failure", username="a" * 500)

    assert len(eventos()[0]["username"]) == MAX_FIELD_LENGTH


def test_audit_no_acepta_campos_libres():
    """R14: la firma es la defensa. No se le puede pasar un secreto."""
    with pytest.raises(TypeError):
        audit("login_failure", password="ContrasenaSecreta")


def test_la_ip_no_se_toma_de_x_forwarded_for(app, eventos):
    """Ese encabezado lo escribe el cliente: registrarlo seria registrar una mentira."""
    with app.test_request_context("/login", headers={"X-Forwarded-For": "1.2.3.4"}):
        audit("login_failure", username="ana")

    assert eventos()[0]["ip"] != "1.2.3.4"


def test_la_contrasena_nunca_aparece_en_el_log(client, usuario, eventos, app):
    """Recorre los caminos reales y revisa el archivo entero."""
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    client.post("/login", data={"username": USERNAME, "password": "otra-mala"})
    client.post("/register", data={
        "username": "beto", "email": "beto@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    })

    with open(app.config["AUDIT_LOG"], encoding="utf-8") as f:
        contenido = f.read()

    assert PASSWORD not in contenido
    assert "otra-mala" not in contenido


def test_register_success_registra_el_id_nuevo(client, eventos):
    client.post("/register", data={
        "username": "beto", "email": "beto@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    })

    registro = eventos()[0]
    assert registro["event"] == "register_success"
    assert registro["user_id"] is not None


def test_register_failure_cuando_el_usuario_ya_existe(client, usuario, eventos):
    client.post("/register", data={
        "username": USERNAME, "email": "otro@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    })

    assert [e["event"] for e in eventos()] == ["register_failure"]


def test_login_success_y_login_failure(client, usuario, eventos):
    client.post("/login", data={"username": USERNAME, "password": "incorrecta"})
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})

    assert [e["event"] for e in eventos()] == ["login_failure", "login_success"]


def test_logout_registra_el_cierre(client, usuario, eventos):
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    client.post("/logout")

    assert [e["event"] for e in eventos()][-1] == "logout"


def test_csrf_failure_se_registra(make_app, eventos):
    """El manejador de CSRFError deja rastro (WBS 4.5.3 + 4.4)."""
    app = make_app(csrf_enabled=True)
    app.test_client().post("/login", data={"username": "ana", "password": "x"})

    ruta = app.config["AUDIT_LOG"]
    with open(ruta, encoding="utf-8") as f:
        registrados = [json.loads(l)["event"] for l in f if l.strip()]

    assert "csrf_failure" in registrados
