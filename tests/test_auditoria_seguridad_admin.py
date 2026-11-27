"""Auditoría de seguridad: endpoints de administración en modo "solo loopback".

Con ``ADMIN_API_KEY`` vacía (valor por defecto de ``.env.example``), ``require_admin``
(``api/app.py``) solo mira la IP del cliente. Un navegador que corre EN el nodo (p. ej.
el dashboard abierto en la RPi) conecta desde 127.0.0.1, así que:

- CSRF: una página ajena hace ``fetch("http://127.0.0.1:8000/network/sync",
  {method: "POST", mode: "no-cors"})``. Es una petición "simple" (sin cuerpo JSON ni
  cabeceras propias): no hay preflight, CORS solo oculta la respuesta y el efecto ocurre.
- DNS rebinding: ``atacante.example`` resuelve primero a su servidor y luego a
  127.0.0.1; desde el punto de vista del navegador es el mismo origen, así que puede
  mandar JSON y leer la respuesta. Llega con ``Host: atacante.example``.

Arreglo mínimo: en modo sin llave, exigir además ``Host`` local (127.0.0.1, localhost,
::1 con o sin puerto) y, si viene ``Origin``, que sea un origen local permitido.
Los tests quedan en xfail estricto hasta el arreglo.
"""
import pytest

from api.cliente_asgi import ClienteASGI
from tests.helpers import make_app


@pytest.fixture
def app_sin_llave(tmp_path):
    app = make_app(tmp_path, admin_api_key="")
    assert not app.state.node.settings.admin_api_key
    return app


@pytest.mark.xfail(strict=True, reason="require_admin no valida Origin: CSRF desde el navegador del nodo")
def test_csrf_origen_ajeno_en_loopback_rechazado(app_sin_llave):
    # Cliente loopback (el navegador del propio nodo) con Origin de otra web.
    c = ClienteASGI(app_sin_llave, client=("127.0.0.1", 50000))
    r = c.post("/network/sync", headers={"Origin": "http://atacante.example"})
    assert r.status_code == 403, r.text


@pytest.mark.xfail(strict=True, reason="require_admin no valida Host: DNS rebinding alcanza la API admin")
def test_dns_rebinding_host_ajeno_en_loopback_rechazado(app_sin_llave):
    c = ClienteASGI(app_sin_llave, client=("127.0.0.1", 50000))
    r = c.post("/mempool/prune", json={},
               headers={"Host": "atacante.example:8000",
                        "Origin": "http://atacante.example:8000"})
    assert r.status_code == 403, r.text


def test_loopback_legitimo_sigue_permitido(app_sin_llave):
    """Control: el uso legítimo desde la propia máquina no debe romperse con el arreglo."""
    c = ClienteASGI(app_sin_llave, client=("127.0.0.1", 50000), base_url="http://127.0.0.1:8000")
    assert c.post("/mempool/prune", json={}).status_code == 200
