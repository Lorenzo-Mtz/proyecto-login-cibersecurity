"""WBS 4.5.3 - Tokens CSRF y logout solo por POST.

Que se prueba y por que cada cosa:

  - El token esta en los tres formularios. Si falta en uno, ese POST queda
    abierto y nada mas lo delata.
  - Un POST sin token, con token basura o con el token de OTRA sesion se
    rechaza. El tercero es el que importa: el token tiene que estar ligado a la
    sesion, no ser un valor cualquiera con el formato correcto.
  - Lo que se rechaza no es solo la respuesta: el efecto no ocurre. Un POST sin
    token no crea la cuenta, no inicia sesion y no cierra la sesion.
  - El logout no acepta GET. Un metodo seguro (GET, HEAD) no debe cambiar
    estado: si lo aceptara, bastaria un <img src="/logout"> en cualquier pagina.
  - El manejador de CSRFError redirige a una ruta FIJA y no al Referer, que
    lo controla el atacante y abriria una open redirect.

Nota: este es el unico archivo que corre con la proteccion encendida. Los demas
usan la fixture `app`, que la apaga para no repetir el token en cada peticion.
"""
import pytest

from conftest import PASSWORD, USERNAME, token_csrf


@pytest.fixture
def app(make_app):
    return make_app(csrf_enabled=True)


@pytest.mark.parametrize("ruta", ["/login", "/register"])
def test_los_formularios_traen_el_token(client, ruta):
    assert 'name="csrf_token"' in client.get(ruta).get_data(as_text=True)


def test_el_formulario_de_logout_trae_el_token(client, usuario):
    client.post("/login", data={
        "username": USERNAME, "password": PASSWORD,
        "csrf_token": token_csrf(client),
    })

    html = client.get("/dashboard").get_data(as_text=True)
    assert 'action="/logout"' in html
    assert 'name="csrf_token"' in html


def test_login_con_token_valido_funciona(client, usuario):
    """El control no puede romper el flujo legitimo."""
    r = client.post("/login", data={
        "username": USERNAME, "password": PASSWORD,
        "csrf_token": token_csrf(client),
    })
    assert r.headers["Location"].endswith("/dashboard")


@pytest.mark.parametrize("token", [None, "", "token-inventado-por-el-atacante"])
def test_login_sin_token_valido_no_inicia_sesion(client, usuario, token):
    datos = {"username": USERNAME, "password": PASSWORD}
    if token is not None:
        datos["csrf_token"] = token

    r = client.post("/login", data=datos)

    assert not r.headers["Location"].endswith("/dashboard")
    with client.session_transaction() as sesion:
        assert "user_id" not in sesion, "la sesion se inicio sin token valido"


def test_el_token_esta_ligado_a_la_sesion(app, usuario):
    """Un token valido de OTRA sesion no debe servir.

    Si sirviera, el atacante solo tendria que pedir /login el mismo y adjuntar
    su propio token: la proteccion seria decorativa.
    """
    token_ajeno = token_csrf(app.test_client())

    otro_cliente = app.test_client()
    otro_cliente.get("/login")  # le da su propia sesion
    r = otro_cliente.post("/login", data={
        "username": USERNAME, "password": PASSWORD, "csrf_token": token_ajeno,
    })

    assert not r.headers["Location"].endswith("/dashboard")


def test_register_sin_token_no_crea_la_cuenta(client, db):
    """Lo que importa no es el codigo de respuesta, sino que el efecto no ocurra."""
    client.post("/register", data={
        "username": "beto", "email": "beto@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    })

    existe = db.execute(
        "SELECT COUNT(*) FROM users WHERE username = 'beto'"
    ).fetchone()[0]
    assert existe == 0


def test_logout_sin_token_no_cierra_la_sesion(client, db, usuario):
    """El caso clasico: un sitio externo forzando el logout de la victima."""
    client.post("/login", data={
        "username": USERNAME, "password": PASSWORD,
        "csrf_token": token_csrf(client),
    })

    client.post("/logout")  # sin token

    assert client.get("/dashboard").status_code == 200, "la sesion se cerro sin token"
    assert db.execute(
        "SELECT session_version FROM users WHERE id = ?", (usuario,)
    ).fetchone()[0] == 0


def test_logout_no_acepta_get(client, usuario):
    """Un metodo seguro no debe cambiar estado: si no, basta un <img src="/logout">."""
    assert client.get("/logout").status_code == 405


def test_el_manejador_de_error_no_redirige_al_referer(client):
    """Redirigir al Referer abriria una open redirect con el dominio legitimo."""
    r = client.post(
        "/login",
        data={"username": "ana", "password": "x"},
        headers={"Referer": "https://sitio-del-atacante.example/trampa"},
    )

    assert r.status_code == 302
    assert "sitio-del-atacante" not in r.headers["Location"]
    assert r.headers["Location"].endswith("/login")
