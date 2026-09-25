"""WBS 6.1 - Cabeceras de seguridad (gap G1 de la Fase 3).

Que se prueba y por que cada cosa:

  - Las cuatro cabeceras salen en TODA respuesta, no solo en las paginas. Un
    302 y un 404 tambien llegan al navegador, y tambien se pueden enmarcar o
    esnifar. Probar solo la pagina de login dejaria fuera la mitad del trafico.
  - La CSP permite `data:` en img-src. Es la parte que se rompe si alguien
    "simplifica" la politica a un solo default-src: el QR del enrolamiento se
    embebe como data: URI, y el sintoma es traicionero -- la pagina carga bien
    y el QR no aparece. Esta prueba existe para que ese cambio se ponga en rojo
    en lugar de descubrirse activando MFA.
  - La CSP NO lleva 'unsafe-inline'. Hoy no hace falta porque las plantillas no
    tienen <script> ni <style> en linea; si alguien agrega uno, la salida facil
    es aflojar la politica, y esta prueba obliga a que sea una decision
    consciente y no un parche.
  - NO se emite Strict-Transport-Security. Es una ausencia deliberada, no un
    olvido (ver el comentario en app.py), y se fija aqui para que si algun dia
    se agrega, alguien tenga que venir a borrar esta prueba y leer por que
    estaba.

Lo que esta suite NO cubre todavia: la respuesta de un 500. `after_request` no
se ejecuta cuando una excepcion no controlada se propaga, asi que esa respuesta
sale sin cabeceras hasta que 6.4 agregue el manejador. Se anade ahi.
"""
import pytest

from conftest import PASSWORD, USERNAME

CABECERAS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def respuestas(client):
    """Una de cada tipo que hoy pasa por after_request."""
    return {
        "200 pagina": client.get("/login"),
        "302 redireccion": client.get("/dashboard"),
        "404 ruta inexistente": client.get("/no-existe"),
    }


@pytest.mark.parametrize("cabecera", CABECERAS)
def test_la_cabecera_sale_en_toda_respuesta(client, cabecera):
    for descripcion, r in respuestas(client).items():
        assert cabecera in r.headers, f"falta {cabecera} en la respuesta {descripcion}"


def test_los_codigos_de_las_respuestas_probadas_son_los_esperados(client):
    """Si una de estas dejara de ser 302 o 404, la prueba de arriba se ablandaria."""
    r = respuestas(client)
    assert r["200 pagina"].status_code == 200
    assert r["302 redireccion"].status_code == 302
    assert r["404 ruta inexistente"].status_code == 404


def test_la_csp_permite_data_en_imagenes(client):
    """Sin esto el QR del enrolamiento se bloquea y la pagina se ve bien igual."""
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "img-src 'self' data:" in csp


def test_la_csp_no_afloja_para_scripts_ni_estilos(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "default-src 'self'" in csp


def test_la_csp_cubre_las_directivas_que_default_src_no_hereda(client):
    """base-uri y form-action no las cubre default-src; son las que se olvidan."""
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "base-uri 'none'" in csp
    assert "form-action 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_referrer_policy_es_no_referrer(client):
    """Mientras el token de recuperacion viaje en el path, es la unica que corta
    del todo la fuga por Referer (TM-34). Si G10 lo mueve al cuerpo, esta
    decision se puede revisar -- y entonces habra que venir aqui."""
    assert client.get("/login").headers["Referrer-Policy"] == "no-referrer"


def test_no_se_emite_hsts(client):
    """Ausencia deliberada: HSTS sobre HTTP plano se ignora, y si tomara efecto
    sin TLS dejaria la aplicacion inalcanzable. Entra con G14."""
    for r in respuestas(client).values():
        assert "Strict-Transport-Security" not in r.headers


def test_las_cabeceras_salen_tambien_con_sesion_abierta(client, usuario):
    """El camino autenticado pasa por el decorador; conviene verlo aparte."""
    client.post("/login", data={"username": USERNAME, "password": PASSWORD})
    r = client.get("/dashboard")
    assert r.status_code == 200
    for cabecera in CABECERAS:
        assert cabecera in r.headers
