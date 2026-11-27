"""El panel y las páginas servidas deben funcionar sin internet (nodos en LAN de campus)."""
import hashlib
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.helpers import make_app

RAIZ = Path(__file__).resolve().parent.parent
EXTERNO = re.compile(r"""<(?:script|link)\b[^>]*?\b(?:src|href)\s*=\s*["'](?:https?:)?//""", re.I)
IMPORT_EXTERNO = re.compile(r"""(?:@import|import\s*\(|from)\s*["']https?://""", re.I)


def _archivos_servidos():
    base = RAIZ / "dashboard"
    return [p for p in list(base.glob("templates/*")) + list(base.glob("static/*.*"))
            if p.suffix in {".html", ".css", ".js"}]


def test_ninguna_plantilla_referencia_recursos_externos():
    archivos = _archivos_servidos()
    assert archivos
    for p in archivos:
        texto = p.read_text(encoding="utf-8")
        assert not EXTERNO.search(texto), f"{p.name} carga un script/hoja externa"
        assert not IMPORT_EXTERNO.search(texto), f"{p.name} importa desde una URL externa"


def test_api_no_incrusta_scripts_externos():
    texto = (RAIZ / "api" / "app.py").read_text(encoding="utf-8")
    assert not EXTERNO.search(texto)


@pytest.mark.asyncio
async def test_vendor_del_panel_se_sirve(tmp_path):
    app = make_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        html = (await c.get("/")).text
        for ruta in ("/static/vendor/chart.umd.js", "/static/vendor/tailwind.css"):
            assert ruta in html
            r = await c.get(ruta)
            assert r.status_code == 200 and len(r.content) > 1000
        assert "Chart.js v4.4.7" in (await c.get("/static/vendor/chart.umd.js")).text


def test_hashes_documentados_coinciden():
    v = RAIZ / "dashboard" / "static" / "vendor"
    readme = (v / "README.md").read_text(encoding="utf-8")
    for nombre in ("chart.umd.js", "tailwind.css"):
        assert hashlib.sha256((v / nombre).read_bytes()).hexdigest() in readme
