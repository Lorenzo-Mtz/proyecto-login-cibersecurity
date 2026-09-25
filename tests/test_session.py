"""WBS 4.5.2 - Decorador @login_required e invalidacion real de sesion (R9).

Que se prueba y por que cada cosa:

  - Sin sesion no se entra a una ruta protegida. Lo basico.
  - Con sesion valida, la vista recibe el usuario en g.user.
  - LL5: Flask guarda la sesion en una cookie FIRMADA del lado del cliente.
    Firmarla evita que se modifique, pero no permite revocarla. Por eso la
    prueba importante no es "el logout limpia la sesion", sino "una cookie
    copiada ANTES del logout ya no sirve DESPUES". Eso exige estado en el
    servidor: la columna session_version.
  - Una cookie de un usuario borrado se rechaza.
  - El logout solo incrementa session_version si la cookie trae la version
    vigente (WHERE id = ? AND session_version = ?), de modo que una cookie
    vieja no puede cerrar las sesiones activas del usuario.
  - Cada rechazo deja un session_rejected en el log: es la señal de una posible
    cookie robada.
"""
from conftest import PASSWORD, USERNAME


def version_en_bd(db, user_id):
    return db.execute(
        "SELECT session_version FROM users WHERE id = ?", (user_id,)
    ).fetchone()[0]


def test_dashboard_sin_sesion_redirige_al_login(client):
    r = client.get("/dashboard")
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/login")


def test_dashboard_con_sesion_valida_muestra_el_usuario(client, usuario):
    """Confirma que el decorador dejo la fila del usuario en g.user."""
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})

    r = client.get("/dashboard")
    assert r.status_code == 200
    assert USERNAME in r.get_data(as_text=True)


def test_cookie_con_session_version_vieja_es_rechazada(client, db, usuario):
    """R9 / LL5: el escenario de la cookie robada.

    Se simula una cookie emitida antes de que la version cambiara.
    """
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})

    db.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?",
               (usuario,))
    db.commit()

    r = client.get("/dashboard")
    assert r.headers["Location"].endswith("/login"), "una cookie vieja no debe servir"


def test_cookie_de_usuario_inexistente_es_rechazada(client, db, usuario):
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})

    db.execute("DELETE FROM users WHERE id = ?", (usuario,))
    db.commit()

    assert client.get("/dashboard").headers["Location"].endswith("/login")


def test_la_cookie_copiada_antes_del_logout_deja_de_servir(client, db, usuario):
    """La prueba que LL5 dice que hay que hacer siempre, y no solo el flujo feliz."""
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    assert client.get("/dashboard").status_code == 200

    with client.session_transaction() as sesion:
        cookie_robada = dict(sesion)

    client.post("/logout")

    # El atacante "reinyecta" la cookie que copio antes del logout.
    with client.session_transaction() as sesion:
        sesion.update(cookie_robada)

    assert client.get("/dashboard").headers["Location"].endswith("/login")


def test_el_logout_incrementa_la_version_en_el_servidor(client, db, usuario):
    """Se mide DESPUES del login, no antes.

    Desde 6.3 el login tambien incrementa la version (gap G3), asi que medir
    desde antes del login haria que esta prueba contara dos incrementos y
    dejara de decir si el logout hace el suyo.
    """
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    tras_login = version_en_bd(db, usuario)

    client.post("/logout")

    assert version_en_bd(db, usuario) == tras_login + 1


def test_una_cookie_vieja_no_puede_cerrar_una_sesion_nueva(client, db, usuario):
    """El AND session_version = ? del UPDATE del logout.

    Sin el, quien tuviera una cookie caducada podria seguir invalidando las
    sesiones activas del usuario legitimo cada vez que quisiera.
    """
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    with client.session_transaction() as sesion:
        cookie_vieja = dict(sesion)

    client.post("/logout")               # sube la version a 1
    version_tras_logout = version_en_bd(db, usuario)

    with client.session_transaction() as sesion:
        sesion.update(cookie_vieja)      # version 0, ya caducada
    client.post("/logout")

    assert version_en_bd(db, usuario) == version_tras_logout


def test_el_rechazo_deja_rastro_en_el_log(client, db, usuario, eventos):
    """session_rejected es la señal de una posible cookie robada."""
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    db.execute("UPDATE users SET session_version = 99 WHERE id = ?", (usuario,))
    db.commit()

    client.get("/dashboard")

    assert "session_rejected" in [e["event"] for e in eventos()]


def test_un_login_nuevo_limpia_la_sesion_anterior(client, usuario):
    """session.clear() antes de escribir: evita session fixation."""
    with client.session_transaction() as sesion:
        sesion["basura_previa"] = "valor-del-atacante"

    client.post("/login", data={"username": USERNAME, "password": PASSWORD})

    with client.session_transaction() as sesion:
        assert "basura_previa" not in sesion
        assert sesion["user_id"] == usuario


def test_volver_a_autenticarse_invalida_la_sesion_anterior(client, db, usuario):
    """WBS 6.3 (gap G3) / V7.2.4: la via de R9 que quedaba abierta.

    El escenario: alguien copia la cookie, el usuario vuelve a iniciar sesion
    --incluso por sospechar que se la robaron-- y hasta 6.3 la cookie copiada
    seguia funcionando, porque login() no tocaba session_version.
    """
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    with client.session_transaction() as sesion:
        cookie_robada = dict(sesion)

    otro = client.application.test_client()
    otro.post("/login", data={"username": USERNAME, "password": PASSWORD})

    with client.session_transaction() as sesion:
        sesion.update(cookie_robada)

    assert client.get("/dashboard").headers["Location"].endswith("/login"), \
        "la cookie anterior sigue sirviendo despues de reautenticarse"
    assert otro.get("/dashboard").status_code == 200, "la sesion nueva debe seguir viva"


def test_el_login_incrementa_la_version_en_el_servidor(client, db, usuario):
    antes = version_en_bd(db, usuario)
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    assert version_en_bd(db, usuario) == antes + 1


def test_la_cookie_de_sesion_lleva_el_prefijo_host(app, client, usuario):
    """WBS 6.2 (gap G2) / V3.3.1.

    ADVERTENCIA: esta prueba comprueba el NOMBRE, y eso es todo lo que el test
    client puede comprobar. Werkzeug no implementa las reglas de prefijo, asi
    que aceptaria una cookie __Host- emitida sin Secure -- que es justo lo que
    un navegador rechazaria. La verificacion real de este control es manual,
    en un navegador, como lo fue la de 4.3.6 con la app autenticadora.
    """
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-session"

    r = client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    set_cookie = r.headers.get("Set-Cookie", "")
    assert set_cookie.startswith("__Host-session="), set_cookie

    # Las tres condiciones que el prefijo exige y que el navegador SI verifica.
    assert "Path=/" in set_cookie
    assert "Domain=" not in set_cookie
