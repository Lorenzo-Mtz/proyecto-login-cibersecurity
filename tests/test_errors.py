"""WBS 6.4 - Manejo global de errores (gap G4, amenaza TM-14).

Que se prueba y por que cada cosa:

  - Un 404 y un 500 devuelven la pagina propia y no la de Werkzeug. Lo que
    importa no es el aspecto: con debug=True la pagina por defecto de un 500 es
    el traceback con codigo fuente, variables locales y consola interactiva --
    el ejemplo canonico de "errores que exponen informacion" del propio OWASP.
  - La respuesta NO contiene el mensaje de la excepcion. Aseverar solo el
    codigo 500 no distingue "se manejo bien" de "se manejo y ademas filtro".
  - El 500 SI deja rastro en el log y el 404 NO. Son decisiones distintas: un
    fallo no previsto es justo lo que hay que poder investigar despues, y un
    404 es ruido de fondo que llenaria el log sin decir nada (LL16).
  - El log registra el evento pero NO el detalle del error. La firma de audit()
    no tiene por donde pasarlo, y esa es la garantia, no la buena intencion
    (4.4.3, R14).
  - Las cabeceras de 6.1 salen tambien en las respuestas de error. Ese era el
    asterisco que quedo abierto en 6.1: after_request no corre cuando una
    excepcion se propaga, asi que hasta que existio este manejador la respuesta
    de un 500 salia sin cabeceras.
"""
import json
import os

import pytest

MENSAJE_SECRETO = "detalle-interno-que-no-debe-salir-42"


@pytest.fixture
def app_con_ruta_rota(make_app):
    """App normal mas una ruta que revienta, para provocar un 500 de verdad."""
    app = make_app()

    @app.route("/revienta")
    def revienta():
        raise RuntimeError(MENSAJE_SECRETO)

    return app


def eventos_de(app):
    from src.audit import audit_logger
    for h in audit_logger.handlers:
        h.flush()
    # El handler abre el archivo con delay=True, asi que si no hubo ningun
    # evento el archivo no existe -- que es justo el caso que comprueba la
    # prueba del 404.
    if not os.path.exists(app.config["AUDIT_LOG"]):
        return []
    with open(app.config["AUDIT_LOG"], encoding="utf-8") as f:
        return [json.loads(l)["event"] for l in f if l.strip()]


def test_una_ruta_inexistente_devuelve_la_pagina_propia(client):
    r = client.get("/no-existe")
    cuerpo = r.get_data(as_text=True)

    assert r.status_code == 404
    assert "Error 404" in cuerpo
    # La pagina por defecto de Werkzeug lleva esta frase; la propia no.
    assert "werkzeug" not in cuerpo.lower()


def test_un_fallo_no_previsto_no_filtra_el_detalle(app_con_ruta_rota):
    r = app_con_ruta_rota.test_client().get("/revienta")
    cuerpo = r.get_data(as_text=True)

    assert r.status_code == 500
    assert MENSAJE_SECRETO not in cuerpo, "la respuesta filtro el mensaje de la excepcion"
    assert "RuntimeError" not in cuerpo
    assert "Traceback" not in cuerpo


def test_un_fallo_no_previsto_queda_registrado(app_con_ruta_rota):
    app_con_ruta_rota.test_client().get("/revienta")
    assert "server_error" in eventos_de(app_con_ruta_rota)


def test_el_registro_del_fallo_no_lleva_el_detalle(app_con_ruta_rota):
    """audit() no acepta campos libres: no hay por donde colar el traceback."""
    app_con_ruta_rota.test_client().get("/revienta")
    with open(app_con_ruta_rota.config["AUDIT_LOG"], encoding="utf-8") as f:
        crudo = f.read()
    assert MENSAJE_SECRETO not in crudo
    assert "Traceback" not in crudo


def test_un_404_no_ensucia_el_log(app_con_ruta_rota):
    """Ruido de fondo: registrarlo llenaria el log sin aportar senal (LL16)."""
    app_con_ruta_rota.test_client().get("/tampoco-existe")
    assert "server_error" not in eventos_de(app_con_ruta_rota)


def test_las_cabeceras_de_seguridad_salen_en_las_respuestas_de_error(app_con_ruta_rota):
    """Cierra el asterisco que quedo abierto en 6.1."""
    cliente = app_con_ruta_rota.test_client()
    for ruta, codigo in [("/no-existe", 404), ("/revienta", 500)]:
        r = cliente.get(ruta)
        assert r.status_code == codigo
        for cabecera in ("Content-Security-Policy", "X-Content-Type-Options",
                         "X-Frame-Options", "Referrer-Policy"):
            assert cabecera in r.headers, f"falta {cabecera} en el {codigo}"


def test_las_excepciones_http_conservan_su_codigo(client):
    """El manejador de Exception no debe tragarse un 405 y convertirlo en 500."""
    assert client.get("/logout").status_code == 405
