"""WBS 6.6 - Politica del nombre de usuario (gap G6) y validaciones de /register.

Cierra ademas parte de la deuda de cobertura anotada en tests/README.md: el
registro solo estaba ejercitado de refilon.

Que se prueba y por que cada cosa:

  - La regla es una LISTA BLANCA. Se prueba que se acepta lo enumerado y se
    rechaza lo demas, no una lista de caracteres "malos" elegidos a mano: una
    prueba con lista negra hereda el mismo defecto que la tendria el codigo,
    que es olvidarse del caracter que nadie penso.
  - Los dos puntos se rechazan EXPLICITAMENTE. No es un caracter cualquiera:
    poder registrarse como `mfa:ana` fue lo que descarto usar prefijos como
    espacio de nombres en el contador de intentos (LL20). Esta prueba fija ese
    hecho, y es lo que vuelve seguro el prefijado de 6.11.
  - Un registro rechazado NO crea la cuenta. Probar solo el redirect no
    distingue "se rechazo" de "se acepto y luego redirigio" (LL12).
  - Los limites se leen de la config, no se escriben a mano: si la politica
    cambia, la prueba sigue midiendo la politica y no un numero viejo.
"""
import pytest

from conftest import PASSWORD

VALIDOS = ["ana", "ana_lopez", "ana.lopez", "ana-lopez", "Usuario123", "a_1.b-2"]
INVALIDOS = [
    ("mfa:ana", "dos puntos: el caso de LL20"),
    ("ana lopez", "espacio"),
    ("ana@lopez", "arroba"),
    ("ana/lopez", "barra"),
    ("ana\\lopez", "barra invertida"),
    ("ana\nlopez", "salto de linea"),
    ("<script>", "marcado HTML"),
    ("ana%20", "codificacion porcentual"),
]


def registrar(client, username, email=None):
    return client.post("/register", data={
        "username": username,
        "email": email or f"{abs(hash(username))}@example.com",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    })


def existe(db, username):
    return db.execute(
        "SELECT COUNT(*) FROM users WHERE username = ?", (username,)
    ).fetchone()[0] == 1


@pytest.mark.parametrize("username", VALIDOS)
def test_se_aceptan_los_nombres_de_la_lista_blanca(client, db, username):
    registrar(client, username)
    assert existe(db, username), f"{username} deberia ser valido"


@pytest.mark.parametrize("username,motivo", INVALIDOS)
def test_se_rechazan_los_nombres_fuera_de_la_lista_blanca(client, db, username, motivo):
    registrar(client, username)
    assert not existe(db, username), f"se creo la cuenta con {motivo}: {username!r}"


def test_el_nombre_vacio_se_rechaza(client, db):
    registrar(client, "")
    assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_se_respetan_los_limites_de_longitud_de_la_config(app, client, db):
    minimo = app.config["USERNAME_MIN_LENGTH"]
    maximo = app.config["USERNAME_MAX_LENGTH"]

    corto = "a" * (minimo - 1)
    registrar(client, corto)
    assert not existe(db, corto), "se acepto un nombre por debajo del minimo"

    largo = "a" * (maximo + 1)
    registrar(client, largo)
    assert not existe(db, largo), "se acepto un nombre por encima del maximo"

    justo = "b" * maximo
    registrar(client, justo)
    assert existe(db, justo), "el maximo exacto debe aceptarse"


def test_el_email_con_formato_invalido_se_rechaza(client, db):
    registrar(client, "usuariovalido", email="esto-no-es-un-email")
    assert not existe(db, "usuariovalido")


def test_un_usuario_duplicado_no_crea_una_segunda_cuenta(client, db):
    registrar(client, "repetido", email="uno@example.com")
    registrar(client, "repetido", email="dos@example.com")
    assert db.execute(
        "SELECT COUNT(*) FROM users WHERE username = ?", ("repetido",)
    ).fetchone()[0] == 1
