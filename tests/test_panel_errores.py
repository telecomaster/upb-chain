"""El panel debe mostrar el ``detail`` del servidor en errores, no "Ver consola"."""
import re
from pathlib import Path

PLANTILLA = Path(__file__).resolve().parent.parent / "dashboard" / "templates" / "index.html"


def _funcion(texto: str, nombre: str) -> str:
    m = re.search(rf"async function {nombre}\(.*?\n}}\n", texto, re.S)
    assert m, nombre
    return m.group(0)


def test_entrenar_modelo_muestra_el_detail_del_servidor():
    cuerpo = _funcion(PLANTILLA.read_text(encoding="utf-8"), "trainModel")
    assert "Ver consola" not in cuerpo
    assert "_detail(data)" in cuerpo and "status" in cuerpo


def test_generar_wallet_muestra_el_detail():
    texto = PLANTILLA.read_text(encoding="utf-8")
    assert "Error al generar wallet: ' + _detail(wallet)" in texto
