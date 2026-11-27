"""Recompensas del laboratorio de ataques (P1-12).

Diseño (simple y explicable en clase):

* El laboratorio NO tiene llave de emisor y no acuña nada. Al terminar, ``scripts/
  laboratorio_ataques.py --direccion UPB...`` imprime un RECIBO: escenario, consenso, semilla,
  dirección del estudiante, un resumen y un digest SHA-256 (detecta recibos alterados).
* El docente (un emisor registrado) entrega el recibo a ``POST /laboratorio/recompensas``. El
  servidor NO confía en el recibo: **vuelve a correr** el escenario (3 a 5 s, nodos en
  loopback) y comprueba que se cumple el logro del escenario. Si sí, el emisor firma una
  ``BADGE_AWARD`` ``lab-<escenario>`` y una ``TOKEN_MINT`` con motivo ``laboratorio:<escenario>``.
* Un recibo inventado no sirve: lo que decide es la repetición. Lo que NO prueba es que ESE
  estudiante lo haya corrido (la dirección es solo una etiqueta); eso lo respalda el docente
  al entregar el recibo, igual que en un premio manual.
* Sin granjas: la insignia es única por dirección y escenario (regla de ``BadgeContract``).
"""
import hashlib
import json
from typing import Callable, Dict, Optional, Tuple

RECIBO_VERSION = 1
PUNTOS_POR_ESCENARIO = 10   # PUPB por escenario completado (puntos de circuito cerrado)


def _doble_gasto_pbft(r: dict) -> bool:
    return (r.get("exito_ataque") is False and r.get("pago_en_cadena_del_comercio") is True
            and r.get("certificado_del_pago") == "OK")


def _sybil_pbft(r: dict) -> bool:
    return r.get("exito_ataque") is False


def _equivocacion_pbft(r: dict) -> bool:
    return (r.get("exito_ataque") is False and r.get("equivocacion_detectada") is True
            and r.get("bloques_distintos_confirmados_en_altura_1") == 1)


# Solo escenarios cuyo desenlace es determinista (la defensa siempre gana). Los de PoW y el
# barrido del 51 % son azarosos: no hay un resultado fijo que pueda re-verificarse.
LOGROS: Dict[Tuple[str, str], Callable[[dict], bool]] = {
    ("doble_gasto", "pbft"): _doble_gasto_pbft,
    ("sybil", "pbft"): _sybil_pbft,
    ("equivocacion", "pbft"): _equivocacion_pbft,
}


def escenarios_premiables() -> list:
    return [{"escenario": e, "consenso": c} for e, c in LOGROS]


def _digest(recibo: dict) -> str:
    cuerpo = {k: v for k, v in recibo.items() if k != "digest"}
    crudo = json.dumps(cuerpo, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(crudo.encode("ascii")).hexdigest()


def construir_recibo(resultado: dict, direccion: str) -> Optional[dict]:
    """Recibo de un escenario completado, o ``None`` si no es premiable o no se cumplió el logro."""
    clave = (resultado.get("escenario"), resultado.get("consenso"))
    logro = LOGROS.get(clave)
    if logro is None or not logro(resultado):
        return None
    recibo = {"version": RECIBO_VERSION, "escenario": clave[0], "consenso": clave[1],
              "semilla": resultado.get("semilla", 1), "direccion": direccion,
              "resumen": {"exito_ataque": resultado.get("exito_ataque")}}
    recibo["digest"] = _digest(recibo)
    return recibo


def validar_recibo(recibo: dict) -> str:
    """Devuelve ``""`` si el recibo está bien formado e íntegro; si no, el motivo."""
    if not isinstance(recibo, dict):
        return "el recibo debe ser un objeto"
    if recibo.get("version") != RECIBO_VERSION:
        return "versión de recibo no soportada"
    escenario, consenso, semilla = recibo.get("escenario"), recibo.get("consenso"), recibo.get("semilla")
    if (escenario, consenso) not in LOGROS:
        return "escenario sin recompensa (solo " + ", ".join(f"{e}/{c}" for e, c in LOGROS) + ")"
    if not isinstance(semilla, int) or isinstance(semilla, bool):
        return "semilla inválida"
    if not isinstance(recibo.get("direccion"), str) or not recibo["direccion"]:
        return "falta la dirección del estudiante"
    if recibo.get("digest") != _digest(recibo):
        return "digest del recibo no coincide (recibo alterado)"
    return ""


def verificar_repitiendo(recibo: dict) -> bool:
    """Vuelve a correr el escenario del recibo y comprueba su logro (bloqueante, segundos)."""
    from security.attacks.laboratorio import ejecutar
    resultado = ejecutar(recibo["escenario"], recibo["consenso"], recibo["semilla"])
    return bool(LOGROS[(recibo["escenario"], recibo["consenso"])](resultado))
