"""
UPB-Chain — Generador de carga sintética etiquetada (P1-6)

Produce un flujo de TX (dicts con la forma de `Transaction.to_dict()`) ordenado en el
tiempo, con tráfico normal y episodios de ataque etiquetados. Es determinista: la misma
semilla produce exactamente el mismo flujo, en cualquier máquina (sin `time.time()`,
sin zona horaria local).

Los datos son SINTÉTICOS: los parámetros del tráfico "normal" son supuestos razonables,
no mediciones de la red real. Los resultados sobre este conjunto no se extrapolan a campo.

Ataques etiquetados (campo `attack`):
    spam_burst         ráfaga de un solo emisor
    fee_outlier        fee muy por encima de lo habitual
    odd_hour           actividad de madrugada
    huge_payload       payload gigante
    replay             mismo payload repetido
    new_address_flood  oleada de direcciones nunca vistas
"""
import hashlib
import random
from dataclasses import dataclass
from typing import Dict, List

from ai.anomaly.detector import ContextoTx, TransactionAnomalyDetector

# Lunes 2026-01-05 00:00 hora de Bolivia (UTC-4) = 04:00 UTC. Constante fija.
EPOCH_INICIO = 1767585600.0
DIA = 86400.0

ATAQUES = ["spam_burst", "fee_outlier", "odd_hour", "huge_payload", "replay", "new_address_flood"]

_TIPOS_NORMALES = [("CREDENTIAL_ISSUE", 0.20), ("CREDENTIAL_REVOKE", 0.05),
                   ("DATA_RECORD", 0.40), ("TOKEN_TRANSFER", 0.30), ("VOTE", 0.05)]


@dataclass
class DatasetTx:
    tx: dict
    label: int          # 0 normal, 1 ataque
    attack: str         # "" si es normal


def _addr(rng: random.Random) -> str:
    return "UPB" + hashlib.sha256(str(rng.getrandbits(64)).encode()).hexdigest()[:30]


def _payload_normal(rng: random.Random, tipo: str) -> dict:
    if tipo == "TOKEN_TRANSFER":
        return {"amount": rng.randint(1, 500)}
    if tipo == "CREDENTIAL_ISSUE":
        return {"credential_id": f"cred-{rng.getrandbits(40):x}", "student": f"est-{rng.randint(1, 5000)}",
                "program": rng.choice(["Ing. Sistemas", "Ing. Industrial", "Ing. Civil", "Administración"]),
                "grade": rng.randint(51, 100)}
    if tipo == "CREDENTIAL_REVOKE":
        return {"credential_id": f"cred-{rng.getrandbits(40):x}", "reason": rng.choice(["error", "duplicado"])}
    if tipo == "VOTE":
        return {"proposal": rng.randint(1, 20), "choice": rng.choice(["si", "no"])}
    return {"record": f"reg-{rng.getrandbits(32):x}", "note": "x" * rng.randint(10, 400)}


def _mk(rng: random.Random, ts: float, sender: str, tipo: str, payload: dict, fee: int) -> dict:
    h = hashlib.sha256(f"{ts}{sender}{tipo}{rng.getrandbits(32)}".encode()).hexdigest()
    return {"tx_id": h, "type": tipo, "sender": sender, "recipient": "DEST", "payload": payload,
            "timestamp": ts, "fee": fee, "nonce": 0}


def _elegir_tipo(rng: random.Random) -> str:
    r, acum = rng.random(), 0.0
    for tipo, p in _TIPOS_NORMALES:
        acum += p
        if r < acum:
            return tipo
    return "DATA_RECORD"


def _normal_dia(rng, dia_ini: float, emisores: List[str], n: int) -> List[DatasetTx]:
    """Tráfico diurno (07–22 h) con una pequeña fracción de madrugada legítima (~1 %)."""
    out = []
    for _ in range(n):
        if rng.random() < 0.01:
            hora = rng.uniform(0, 5)
        else:
            hora = rng.uniform(7, 22)
        tipo = _elegir_tipo(rng)
        fee = rng.choices([0, 1, 2, 3, 5, 8], weights=[2, 30, 30, 20, 12, 6])[0]
        out.append(DatasetTx(_mk(rng, dia_ini + hora * 3600, rng.choice(emisores), tipo,
                                 _payload_normal(rng, tipo), fee), 0, ""))
    return out


def _episodio(rng, ataque: str, t0: float, emisores: List[str]) -> List[DatasetTx]:
    out: List[DatasetTx] = []

    def add(ts, sender, tipo, payload, fee):
        out.append(DatasetTx(_mk(rng, ts, sender, tipo, payload, fee), 1, ataque))

    if ataque == "spam_burst":
        s = rng.choice(emisores)
        for _ in range(rng.randint(25, 50)):
            tipo = "DATA_RECORD"
            add(t0 + rng.uniform(0, 30), s, tipo, _payload_normal(rng, tipo), rng.choice([1, 2]))
    elif ataque == "fee_outlier":
        for _ in range(rng.randint(3, 8)):
            tipo = _elegir_tipo(rng)
            add(t0 + rng.uniform(0, 600), rng.choice(emisores), tipo, _payload_normal(rng, tipo),
                rng.randint(150, 3000))
    elif ataque == "odd_hour":
        base = t0 - (t0 - EPOCH_INICIO) % DIA + rng.uniform(0.5, 4.5) * 3600
        s = rng.choice(emisores)
        for _ in range(rng.randint(5, 15)):
            tipo = _elegir_tipo(rng)
            add(base + rng.uniform(0, 1800), s, tipo, _payload_normal(rng, tipo), rng.choice([1, 2, 3]))
    elif ataque == "huge_payload":
        for _ in range(rng.randint(2, 6)):
            add(t0 + rng.uniform(0, 600), rng.choice(emisores), "DATA_RECORD",
                {"record": "blob", "note": "x" * rng.randint(15000, 120000)}, rng.choice([1, 2, 3]))
    elif ataque == "replay":
        p = {"record": f"reg-{rng.getrandbits(32):x}", "note": "copiado"}
        for _ in range(rng.randint(8, 20)):
            add(t0 + rng.uniform(0, 40), rng.choice(emisores), "DATA_RECORD", dict(p), rng.choice([1, 2]))
    elif ataque == "new_address_flood":
        for _ in range(rng.randint(15, 30)):
            tipo = _elegir_tipo(rng)
            add(t0 + rng.uniform(0, 25), _addr(rng), tipo, _payload_normal(rng, tipo), rng.choice([0, 1]))
    return out


def generar_dataset(seed: int = 7, dias: int = 14, tx_normales_por_dia: int = 300,
                    episodios_por_ataque: int = 4, n_emisores: int = 40) -> List[DatasetTx]:
    """Flujo completo ordenado por timestamp. Determinista para una semilla dada."""
    rng = random.Random(seed)
    emisores = [_addr(rng) for _ in range(n_emisores)]
    out: List[DatasetTx] = []
    for d in range(dias):
        out.extend(_normal_dia(rng, EPOCH_INICIO + d * DIA, emisores, tx_normales_por_dia))
    for ataque in ATAQUES:
        for k in range(episodios_por_ataque):
            # estratificado: un episodio por tramo del periodo, para que haya ataques en entrenamiento y prueba
            t0 = EPOCH_INICIO + (k + rng.random()) * dias * DIA / episodios_por_ataque
            out.extend(_episodio(rng, ataque, t0, emisores))
    out.sort(key=lambda r: (r.tx["timestamp"], r.tx["tx_id"]))
    return out


def extraer_matriz(registros: List[DatasetTx]) -> List[List[float]]:
    """Características (incluido el contexto) calculadas en orden temporal sobre todo el flujo."""
    det = TransactionAnomalyDetector()
    ctx = ContextoTx()
    X = []
    for r in registros:
        X.append(det.extract_features(r.tx, ctx))
        ctx.observe(r.tx)
    return X


def dividir_cronologico(registros: List[DatasetTx], X: List[List[float]], frac_train: float = 0.7):
    """Entrenamiento = primeros días; prueba = últimos. El split se fija antes de ver etiquetas."""
    ult = registros[-1].tx["timestamp"]
    corte = EPOCH_INICIO + (ult - EPOCH_INICIO) * frac_train
    i = next((k for k, r in enumerate(registros) if r.tx["timestamp"] >= corte), len(registros))
    return (registros[:i], X[:i]), (registros[i:], X[i:])


def resumen(registros: List[DatasetTx]) -> Dict[str, int]:
    r: Dict[str, int] = {"normal": 0}
    for x in registros:
        r[x.attack or "normal"] = r.get(x.attack or "normal", 0) + 1
    return r
