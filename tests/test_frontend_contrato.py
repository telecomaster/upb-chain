"""Contrato front-end / API: lo que el JS del dashboard, la billetera y el kiosco pide existe de verdad.

Extrae de forma estática las rutas que llama el JS (fetch, EventSource, imágenes) y comprueba
que cada una coincide con una ruta y un método reales de ``make_app``; que los eventos SSE que
escucha el dashboard son los que publica el servidor; que los ids del DOM que busca el JS
existen en el HTML, y que los endpoints de administración solo se llaman con ``X-API-Key``.
"""
import re
from pathlib import Path

import pytest

from tests.helpers import make_app

RAIZ = Path(__file__).resolve().parent.parent
PLANTILLAS = RAIZ / "dashboard" / "templates"
ESTATICOS = RAIZ / "dashboard" / "static"

ARCHIVOS_JS = {
    "index.html": PLANTILLAS / "index.html",
    "billetera.js": ESTATICOS / "billetera.js",
    "kiosco.js": ESTATICOS / "kiosco.js",
}

LLAMADAS = r"(?:fetchJSON|fetch|obtener|getJson|_postIssuer|EventSource)"
# Literal de ruta que empieza por "/" (con o sin "API + " delante) tras una llamada.
RE_LLAMADA = re.compile(LLAMADAS + r"\(\s*(?:API\s*\+\s*)?(?P<q>['\"`])(?P<ruta>/[^'\"`]*)(?P=q)")
RE_IMG = re.compile(r"""<img src="(?P<ruta>/credentials/[^"]*)\"""")


def _leer(ruta: Path) -> str:
    return ruta.read_text(encoding="utf-8")


def _normalizar(ruta: str) -> str:
    """``/blocks/${i}?x=1`` -> ``/blocks/{p}``; ``/tx/' + id`` ya llega cortado en la comilla."""
    ruta = ruta.split("?")[0]
    ruta = re.sub(r"\$\{[^}]*\}", "{p}", ruta)
    return ruta.rstrip("/") if len(ruta) > 1 else ruta


def llamadas_de(nombre: str):
    """Lista ``(ruta_normalizada, metodo, ruta_original)`` que hace un archivo JS."""
    texto = _leer(ARCHIVOS_JS[nombre])
    salida = []
    for m in RE_LLAMADA.finditer(texto):
        ruta = m.group("ruta")
        # Concatenación ``'/blocks/' + idx``: el literal termina en "/" y sigue un parámetro.
        resto = texto[m.end(): m.end() + 12]
        if ruta.endswith("/") and re.match(r"\s*\+", resto):
            ruta += "{p}"
        # ``'/tx/' + id + '/proof'``: se une el tramo literal siguiente.
        cola = re.match(r"\s*\+\s*[\w.]+\s*\+\s*(['\"])(?P<t>/[^'\"]*)\1", texto[m.end():])
        if cola and ruta.endswith("{p}"):
            ruta += cola.group("t")
        ventana = texto[m.start(): m.end() + 260]
        metodo = "GET"
        if m.group(0).startswith("_postIssuer"):
            metodo = "POST"
        else:
            mm = re.search(r"method\s*:\s*['\"](GET|POST|PUT|DELETE)['\"]", ventana)
            if mm:
                metodo = mm.group(1)
        if "${kind}" in ruta:    # loadCredentialHistory('issuer' | 'student')
            for tipo in sorted(set(re.findall(r"loadCredentialHistory\('(\w+)'\)", texto))):
                salida.append((_normalizar(ruta.replace("${kind}", tipo)), metodo, ruta))
            continue
        salida.append((_normalizar(ruta), metodo, ruta))
    if nombre == "index.html":
        for m in RE_IMG.finditer(texto):
            salida.append((_normalizar(m.group("ruta")), "GET", m.group("ruta")))
    return salida


@pytest.fixture(scope="module")
def rutas_reales(tmp_path_factory):
    """``[(regex, {métodos})]`` de la app real (vía el esquema OpenAPI)."""
    app = make_app(tmp_path_factory.mktemp("contrato"))
    rutas = []
    for ruta, ops in app.openapi()["paths"].items():
        patron = "^" + re.sub(r"\{[^}]+\}", "[^/]+", ruta) + "$"
        rutas.append((re.compile(patron), {m.upper() for m in ops}, ruta))
    return rutas


def _existe(rutas_reales, ruta: str, metodo: str) -> bool:
    ejemplo = ruta.replace("{p}", "x")
    return any(rx.match(ejemplo) and metodo in metodos for rx, metodos, _ in rutas_reales)


@pytest.mark.parametrize("nombre", sorted(ARCHIVOS_JS))
def test_cada_ruta_que_llama_el_js_existe_con_su_metodo(nombre, rutas_reales):
    llamadas = llamadas_de(nombre)
    assert llamadas, f"{nombre}: la extracción no encontró ninguna llamada (¿cambió el estilo?)"
    faltan = [(m, r) for n, m, r in llamadas if not _existe(rutas_reales, n, m)]
    assert not faltan, f"{nombre} llama rutas que la API no tiene: {faltan}"


def test_el_inventario_cubre_las_llamadas_conocidas():
    """Salvaguarda de la extracción: si dejara de ver rutas clave, el test anterior sería vacío."""
    todas = {(n, m) for nombre in ARCHIVOS_JS for n, m, _ in llamadas_de(nombre)}
    for esperado in [("/stats", "GET"), ("/blocks/mine", "POST"), ("/credentials/issue", "POST"),
                     ("/credentials/{p}/disclose-verify", "POST"), ("/tokens/award/csv", "POST"),
                     ("/accounts/{p}", "GET"), ("/transactions", "POST"), ("/tx/{p}/proof", "GET"),
                     ("/credentials/verify/{p}", "GET"), ("/events", "GET"),
                     ("/blocks/{p}/certificate", "GET"), ("/laboratorio/recompensas", "POST"),
                     ("/catalog", "GET"), ("/tokens/event-codes/{p}", "GET")]:
        assert esperado in todas, esperado


def test_endpoints_de_administracion_solo_con_llave():
    """Las rutas con ``require_admin`` solo se llaman desde ``fetchJSON`` (que añade X-API-Key)."""
    fuente = _leer(RAIZ / "api" / "app.py")
    admin = {(m.group(2).upper(), m.group(3)) for m in re.finditer(
        r"@router\.(get|post)\(\s*\"([^\"]+)\"[^)]*require_admin", fuente)
        for m in [re.match(r"(.*)", m.group(0)) and re.search(
            r"@router\.(get|post)\(\s*\"([^\"]+)\"", m.group(0)) and
            type("M", (), {"group": lambda s, i, mm=re.search(
                r"@router\.(get|post)\(\s*\"([^\"]+)\"", m.group(0)): (
                    None, mm.group(1), mm.group(1), mm.group(2))[i]})()]}
    # (método, ruta) de administración, p. ej. ("POST", "/blocks/mine")
    admin = {(a, b) for a, b in admin}
    for nombre in ("billetera.js", "kiosco.js"):
        for n, m, _ in llamadas_de(nombre):
            assert (m, n) not in admin, f"{nombre} llama a {n} (admin) sin X-API-Key"
    html = _leer(ARCHIVOS_JS["index.html"])
    # Solo un fetch(...) en el dashboard: el de fetchJSON, que envía la llave si existe.
    assert len(re.findall(r"\bfetch\(", html)) == 1
    assert "'X-API-Key'" in html.split("async function fetchJSON")[1][:600]
    assert ("POST", "/blocks/mine") in admin and ("POST", "/ai/train") in admin


def test_eventos_sse_que_escucha_el_dashboard_los_publica_el_servidor():
    html = _leer(ARCHIVOS_JS["index.html"])
    escuchados = set(re.findall(r"es\.addEventListener\('(\w+)'", html))
    publicados = set()
    for f in (RAIZ / "api").glob("*.py"):
        publicados |= set(re.findall(r"publish\(\s*\"(\w+)\"", _leer(f)))
    assert escuchados, "no se encontraron suscripciones SSE"
    assert escuchados <= publicados, f"eventos que el servidor nunca emite: {escuchados - publicados}"


def _ids_html(texto: str) -> set:
    return set(re.findall(r"""\bid=["']([^"']+)["']""", texto))


@pytest.mark.parametrize("js, html, patron", [
    ("index.html", "index.html", r"getElementById\(\s*'([^']+)'\s*\)"),
    ("billetera.js", "billetera.html", r"\$\(\s*'([^']+)'\s*\)"),
    ("kiosco.js", "kiosco.html", r"(?:getElementById|\$)\(\s*'([^']+)'\s*\)"),
])
def test_ids_del_dom_que_busca_el_js_existen_en_el_html(js, html, patron):
    usados = set(re.findall(patron, _leer(ARCHIVOS_JS[js])))
    assert usados
    existentes = _ids_html(_leer(PLANTILLAS / html))
    # Ids que el propio JS crea (p. ej. filas de detalle de bloque) no están en la plantilla.
    dinamicos = {"block-detail-row-"}
    faltan = {i for i in usados - existentes if not any(i.startswith(d) for d in dinamicos)}
    assert not faltan, f"{js} busca ids que {html} no tiene: {sorted(faltan)}"


def test_mensaje_de_postissuer_usa_campos_que_devuelve_cada_endpoint():
    """Regresión: /laboratorio/recompensas devuelve badge_tx_id/mint_tx_id (no tx_id) y el panel
    mostraba "Enviado (TX undefined)". Cada campo que lee el mensaje existe en alguna respuesta."""
    html = _leer(ARCHIVOS_JS["index.html"])
    cuerpo = html.split("async function _postIssuer")[1].split("\nfunction ")[0]
    leidos = set(re.findall(r"data\.(\w+)", cuerpo))
    devueltos = set(re.findall(r'"(\w+)":', _leer(RAIZ / "api" / "app.py")))
    assert {"badge_tx_id", "mint_tx_id", "count", "tx_id"} <= leidos
    assert leidos <= devueltos, leidos - devueltos
