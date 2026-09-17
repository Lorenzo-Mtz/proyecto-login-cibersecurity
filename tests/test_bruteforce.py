"""WBS 4.1 - Proteccion contra fuerza bruta (R10).

Que se prueba y por que cada cosa:

  - El umbral es 5 y no 6: un `>` en lugar de `>=` en is_blocked() haria que la
    politica escrita y la implementada no coincidieran.
  - El bloqueo vence a credenciales CORRECTAS: el guard va antes de verificar
    la contrasena, asi que no se le puede "ganar" acertando.
  - Un intento bloqueado NO se registra: si se registrara, cualquiera podria
    mantener bloqueada la cuenta de otro para siempre (DoS de cuenta, R10).
  - Bloqueado y fallo normal tardan lo mismo: sin el checkpw contra DUMMY_HASH
    en el camino bloqueado, la latencia delata que la cuenta existe y esta
    bajo ataque. Es un oraculo invisible en el navegador.
  - Una cuenta inexistente se bloquea igual: por eso login_attempts no tiene
    FOREIGN KEY a users. Si la tuviera, el bloqueo revelaria que cuentas existen.
  - El bloqueo se libera solo: nunca es permanente.
  - login_blocked es un evento distinto de login_failure en el log.

Ojo con los tiempos (ver LL10): cada request cuesta ~330 ms por bcrypt, asi que
una ventana corta puede expirar a media prueba y hacer que se mida otra cosa.
"""
import time

import pytest

from conftest import PASSWORD, USERNAME

# Holgada frente al costo de bcrypt, pero corta para que la prueba de
# expiracion no tarde minutos.
VENTANA = 10


@pytest.fixture
def app(make_app):
    return make_app(LOGIN_WINDOW_SECONDS=VENTANA)


def intentar(client, username, password):
    """Devuelve (destino_de_la_redireccion, segundos). /dashboard = entro."""
    t0 = time.perf_counter()
    r = client.post("/login", data={"username": username, "password": password})
    return r.headers["Location"], time.perf_counter() - t0


def filas(db, username):
    return db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ?", (username,)
    ).fetchone()[0]


def test_umbral_es_exacto(app, client, db, usuario):
    """Con MAX-1 fallos todavia se puede entrar; el fallo MAX bloquea."""
    maximo = app.config["LOGIN_MAX_ATTEMPTS"]

    for _ in range(maximo - 1):
        intentar(client, USERNAME, "incorrecta")

    destino, _ = intentar(client, USERNAME, PASSWORD)
    assert destino.endswith("/dashboard"), "MAX-1 fallos no deben bloquear"


def test_login_exitoso_reinicia_el_contador(client, db, usuario):
    """WBS 4.1.4: quien fallo y luego acerto no arrastra esos fallos."""
    for _ in range(3):
        intentar(client, USERNAME, "incorrecta")
    assert filas(db, USERNAME) == 3

    intentar(client, USERNAME, PASSWORD)
    assert filas(db, USERNAME) == 0


def test_bloqueo_vence_a_la_contrasena_correcta(app, client, db, usuario):
    """La prueba clave: acertar no sirve de nada durante el bloqueo."""
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        intentar(client, USERNAME, "incorrecta")

    destino, _ = intentar(client, USERNAME, PASSWORD)
    assert destino.endswith("/login"), "el bloqueo debe ganarle a credenciales validas"


def test_intento_bloqueado_no_prolonga_el_bloqueo(app, client, db, usuario):
    """R10: si el intento bloqueado contara, se podria bloquear a alguien a voluntad.

    Se compara MAX(id) y no COUNT(*): si se insertara una fila y la limpieza de
    record_failed_attempt borrara una vieja, el conteo no cambiaria y el bug
    pasaria desapercibido (LL10).
    """
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        intentar(client, USERNAME, "incorrecta")

    sql = "SELECT MAX(id) FROM login_attempts WHERE username = ?"
    antes = db.execute(sql, (USERNAME,)).fetchone()[0]

    for _ in range(3):
        intentar(client, USERNAME, "incorrecta")

    assert db.execute(sql, (USERNAME,)).fetchone()[0] == antes


def test_sin_oraculo_por_latencia(app, client, db, usuario):
    """El camino bloqueado debe tardar lo mismo que un fallo normal.

    Sin el bcrypt.checkpw contra DUMMY_HASH serian ~2 ms contra ~340 ms, y
    medir el tiempo revelaria que la cuenta existe y esta bajo ataque.
    """
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        intentar(client, USERNAME, "incorrecta")

    _, t_bloqueado = intentar(client, USERNAME, PASSWORD)
    _, t_fallo_normal = intentar(client, "otro_usuario_cualquiera", "incorrecta")

    ratio = t_bloqueado / t_fallo_normal
    assert 0.4 <= ratio <= 2.5, (
        f"latencias muy distintas: bloqueado={t_bloqueado * 1000:.0f} ms, "
        f"fallo normal={t_fallo_normal * 1000:.0f} ms (ratio {ratio:.2f})"
    )


def test_cuenta_inexistente_tambien_se_bloquea(app, client, db):
    """Sin esto el bloqueo seria un oraculo de que cuentas existen.

    Depende de que login_attempts NO tenga FOREIGN KEY a users.
    """
    maximo = app.config["LOGIN_MAX_ATTEMPTS"]
    for _ in range(maximo):
        intentar(client, "cuenta_que_no_existe", "incorrecta")

    assert filas(db, "cuenta_que_no_existe") == maximo


def test_el_bloqueo_expira_solo(app, client, db, usuario):
    """Nunca es permanente: al vencer la ventana la cuenta vuelve a funcionar."""
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        intentar(client, USERNAME, "incorrecta")
    assert intentar(client, USERNAME, PASSWORD)[0].endswith("/login")

    time.sleep(VENTANA + 1)

    assert intentar(client, USERNAME, PASSWORD)[0].endswith("/dashboard")
    assert filas(db, USERNAME) == 0


def test_login_blocked_es_un_evento_propio(app, client, db, usuario, eventos):
    """Mezclarlo con login_failure borraria la señal de ataque en el log."""
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        intentar(client, USERNAME, "incorrecta")
    for _ in range(3):
        intentar(client, USERNAME, "incorrecta")

    tipos = [e["event"] for e in eventos()]
    assert tipos.count("login_failure") == app.config["LOGIN_MAX_ATTEMPTS"]
    assert tipos.count("login_blocked") == 3
