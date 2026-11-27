"""
UPB-Chain — Detección federada de anomalías entre nodos (Idea 6).

NO es consenso y no comparte datos: cada nodo conserva su Isolation Forest local y sólo
intercambia con sus pares un *resumen compacto* de lo que vio al entrenar (mediana y MAD de
5 características de magnitud, más el número de muestras), no el modelo ni las TX.

1. Referencia federada. Con los resúmenes de los n nodos (el propio incluido) se agrega, con
   peso w_i = n_i / Σn:
       mediana = Σ w_i·med_i
       escala  = sqrt( Σ w_i·(mad_i² + (med_i − mediana)²) )      (varianza agrupada)
   Es una aproximación explicable (la mediana de medianas no es la mediana global), no un
   cálculo exacto sobre los datos juntos.
2. Puntaje federado. z_j = |x_j − mediana_j| / max(1,4826·escala_j, ESCALA_MINIMA) por
   característica (espacio log1p, el mismo del detector); puntaje = max_j z_j. Una TX es
   "anómala federada" si puntaje >= Z_UMBRAL. Constantes fijadas a priori, no ajustadas.
3. Alerta federada. Cuando un nodo marca una TX (IF local o puntaje federado) difunde un
   `AI_FLAG` {tx_id, sender, score, z, top}. Si >= k nodos DISTINTOS marcan el mismo tx_id (o el
   mismo emisor) dentro de `ventana` segundos, se dispara una alerta `FEDERATED_ANOMALY` (una
   vez por clave). Identidad: el CN del certificado con TLS; sin TLS, el `node_id` declarado
   (suplantable: sólo es defensa real con TLS + lista blanca).

Límites: tamaño de resumen y de bandera, banderas por minuto por par, claves y pares
acotados, deduplicación por (nodo, clave).
"""
import hashlib
import json
import math
import threading
import time
from collections import OrderedDict, deque
from typing import Deque, Dict, List, Optional, Tuple

FED_IDX = [0, 1, 5, 6, 7]    # payload_size, fee, sender_rate, payload_repeats, new_senders_recent
FED_NAMES = ["payload_size", "fee", "sender_rate", "payload_repeats", "new_senders_recent"]
RESUMEN_VERSION = 1
Z_UMBRAL = 6.0               # a priori; no se ajustó con datos de prueba
ESCALA_MINIMA = 0.5          # evita dividir por ~0 cuando el MAD de una característica discreta es 0
MAX_RESUMEN_BYTES = 4096
MAX_FLAG_BYTES = 2048
MAX_PARES = 64
MAX_CLAVES = 2000
MAX_FLAGS_POR_MIN = 120      # por par


def hash_tipos(type_map: dict) -> str:
    return hashlib.sha256(json.dumps(type_map, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def construir_resumen(mediana: List[float], mad: List[float], n: int, type_map: dict,
                      model_version: int) -> dict:
    """Resumen compartible (sólo estadísticos; `mediana`/`mad` de 9 columnas en espacio log1p)."""
    return {"v": RESUMEN_VERSION, "model_version": model_version, "features": FED_NAMES,
            "type_map_hash": hash_tipos(type_map), "n": int(n),
            "mediana": [round(float(mediana[j]), 6) for j in FED_IDX],
            "mad": [round(float(mad[j]), 6) for j in FED_IDX]}


def _finito(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and abs(v) < 1e6


def validar_resumen(r, type_map_hash: str, model_version: int) -> Optional[str]:
    """None si es utilizable; si no, el motivo del rechazo."""
    if not isinstance(r, dict):
        return "no es un objeto"
    if len(json.dumps(r, default=str)) > MAX_RESUMEN_BYTES:
        return "demasiado grande"
    if r.get("v") != RESUMEN_VERSION or r.get("model_version") != model_version:
        return "versión distinta"
    if r.get("features") != FED_NAMES or r.get("type_map_hash") != type_map_hash:
        return "características o mapa de tipos distintos"
    n = r.get("n")
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 10**9:
        return "n inválido"
    for k in ("mediana", "mad"):
        v = r.get(k)
        if not isinstance(v, list) or len(v) != len(FED_IDX) or not all(_finito(x) for x in v):
            return f"{k} inválido"
    if any(x < 0 for x in r["mad"]):
        return "mad negativo"
    return None


def agregar(resumenes: List[Optional[dict]]) -> Optional[dict]:
    """Referencia federada: media ponderada de medianas y varianza agrupada (ver docstring)."""
    rs = [r for r in resumenes if r]
    total = sum(r["n"] for r in rs)
    if total <= 0:
        return None
    m = len(FED_IDX)
    med = [sum(r["n"] * r["mediana"][j] for r in rs) / total for j in range(m)]
    esc = [math.sqrt(sum(r["n"] * (r["mad"][j] ** 2 + (r["mediana"][j] - med[j]) ** 2) for r in rs) / total)
           for j in range(m)]
    return {"nodos": len(rs), "n": total, "features": FED_NAMES,
            "mediana": [round(x, 6) for x in med], "escala": [round(x, 6) for x in esc]}


def puntaje(x_log: List[float], ref: dict) -> Tuple[float, List[dict]]:
    """(max z, detalle por característica ordenado) para un vector de 9 columnas ya en log1p."""
    det = []
    for k, j in enumerate(FED_IDX):
        s = max(1.4826 * ref["escala"][k], ESCALA_MINIMA)
        det.append({"caracteristica": FED_NAMES[k], "z": round(abs(x_log[j] - ref["mediana"][k]) / s, 3)})
    det.sort(key=lambda e: (-e["z"], e["caracteristica"]))
    return det[0]["z"], det


class FederadoIA:
    """Estado federado de un nodo (hilo-seguro). Sin red: `P2PNode` entrega y recoge mensajes."""

    def __init__(self, node_id: str, k: int = 2, ventana: float = 300.0,
                 type_map: Optional[dict] = None, model_version: int = 2, reloj=time.time):
        self.node_id, self.k, self.ventana, self._reloj = node_id, max(1, int(k)), float(ventana), reloj
        self._tm_hash = hash_tipos(type_map or {})
        self._mv = model_version
        self._lock = threading.Lock()
        self._local: Optional[dict] = None
        self._peers: Dict[str, dict] = {}
        self._flags: "OrderedDict[str, Dict[str, float]]" = OrderedDict()   # clave -> {nodo: ts}
        self._alertadas: "OrderedDict[str, None]" = OrderedDict()
        self._tasa: Dict[str, Deque[float]] = {}
        self.recientes: Deque[dict] = deque(maxlen=50)
        self.rechazos = 0

    # ── Resúmenes ─────────────────────────────────────────────────────────────
    def set_local(self, resumen: Optional[dict]) -> None:
        with self._lock:
            self._local = resumen

    def local(self) -> Optional[dict]:
        with self._lock:
            return self._local

    def recibir_resumen(self, origen: str, resumen) -> bool:
        if not origen or origen == self.node_id:
            return False
        if validar_resumen(resumen, self._tm_hash, self._mv):
            self.rechazos += 1
            return False
        with self._lock:
            if origen not in self._peers and len(self._peers) >= MAX_PARES:
                self.rechazos += 1
                return False
            self._peers[origen] = {**resumen, "recibido": self._reloj()}
        return True

    def referencia(self) -> Optional[dict]:
        with self._lock:
            return agregar([self._local] + list(self._peers.values()))

    def puntuar(self, x_log: List[float]) -> Optional[Tuple[float, List[dict]]]:
        ref = self.referencia()
        return puntaje(x_log, ref) if ref else None

    # ── Banderas ──────────────────────────────────────────────────────────────
    def _registrar(self, clave: str, nodo: str, ahora: float) -> Optional[dict]:
        d = self._flags.setdefault(clave, {})
        d[nodo] = ahora
        self._flags.move_to_end(clave)
        while len(self._flags) > MAX_CLAVES:
            self._flags.popitem(last=False)
        vivos = sorted(n for n, t in d.items() if ahora - t <= self.ventana)
        if len(vivos) >= self.k and clave not in self._alertadas:
            self._alertadas[clave] = None
            while len(self._alertadas) > MAX_CLAVES:
                self._alertadas.popitem(last=False)
            return {"clave": clave, "nodos": vivos}
        return None

    def _procesar(self, nodo: str, data: dict) -> List[dict]:
        ahora = self._reloj()
        alertas = []
        with self._lock:
            self.recientes.append({"nodo": nodo, "tx_id": data["tx_id"], "sender": data["sender"],
                                   "score": data["score"], "z": data["z"], "top": data["top"], "ts": ahora})
            for clave in ("tx:" + data["tx_id"], "sender:" + data["sender"]):
                a = self._registrar(clave, nodo, ahora)
                if a:
                    a.update(tx_id=data["tx_id"], sender=data["sender"], score=data["score"], top=data["top"])
                    alertas.append(a)
        return alertas[:1]      # una sola alerta por bandera (la de la TX gana a la del emisor)

    @staticmethod
    def armar_flag(node_id: str, tx_id: str, sender: str, score: float, z: float, top: List[str]) -> dict:
        return {"node_id": node_id, "tx_id": str(tx_id)[:64], "sender": str(sender)[:128],
                "score": round(float(score), 4), "z": round(float(z), 3),
                "top": [str(t)[:40] for t in top[:3]]}

    def marcar_local(self, tx_id: str, sender: str, score: float, z: float,
                     top: List[str]) -> Tuple[dict, List[dict]]:
        """Este nodo marca una TX: devuelve (bandera a difundir, alertas k-de-n que se disparan)."""
        flag = self.armar_flag(self.node_id, tx_id, sender, score, z, top)
        return flag, self._procesar(self.node_id, flag)

    def recibir_flag(self, origen: str, data) -> List[dict]:
        """Bandera de un par (origen = identidad autenticada). [] si se descarta."""
        if not origen or origen == self.node_id or not isinstance(data, dict):
            return []
        try:
            if len(json.dumps(data)) > MAX_FLAG_BYTES:
                raise ValueError("grande")
            top = data.get("top", [])
            if not (isinstance(data["tx_id"], str) and isinstance(data["sender"], str)
                    and isinstance(top, list) and _finito(data["score"]) and _finito(data["z"])):
                raise ValueError("tipos")
            flag = self.armar_flag(origen, data["tx_id"], data["sender"], data["score"], data["z"],
                                   [t for t in top if isinstance(t, str)])
        except (KeyError, ValueError, TypeError):
            self.rechazos += 1
            return []
        ahora = self._reloj()
        with self._lock:
            if origen not in self._tasa and len(self._tasa) >= MAX_PARES:
                self.rechazos += 1
                return []
            q = self._tasa.setdefault(origen, deque())
            while q and ahora - q[0] > 60:
                q.popleft()
            if len(q) >= MAX_FLAGS_POR_MIN:
                self.rechazos += 1
                return []
            q.append(ahora)
        return self._procesar(origen, flag)

    def estado(self) -> dict:
        with self._lock:
            recientes = list(self.recientes)
            pares = {k: {x: v[x] for x in ("n", "mediana", "mad", "recibido")} for k, v in self._peers.items()}
            local = self._local
            alertas = len(self._alertadas)
        return {"k": self.k, "ventana": self.ventana, "local": local, "pares": pares,
                "referencia": self.referencia(), "banderas_recientes": recientes,
                "alertas_disparadas": alertas, "rechazos": self.rechazos, "z_umbral": Z_UMBRAL}
