"""
Carrera de consensos (P1-1, idea 2 del ROADMAP): la misma carga en PoW y en PBFT.

Levanta 4 nodos EN EL MISMO PROCESO (``create_app`` + P2P real por loopback,
como las pruebas), les envía la misma carga con semilla y mide, por TX, el
tiempo desde que entra al mempool de un nodo hasta que está en la cadena de
LOS CUATRO nodos. Escribe:

    <salida>/carrera_consensos.csv        una fila por TX (modo, latencia...)
    <salida>/carrera_consensos.md         resumen por modo

Qué se mide y qué NO (leer antes de citar los números):
- Medido en la máquina donde se ejecuta, con red en proceso (loopback) y los
  4 nodos compartiendo un intérprete de Python (GIL): NO son números de las
  Raspberry Pi ni de una LAN. Las mediciones en hardware son P1-10.
- PoW: los 4 nodos minan solo cuando hay TXs pendientes (igual que el primario
  PBFT, que solo propone si hay TXs), con la dificultad fija ``--bits`` (la
  regla de reajuste no actúa dentro de la primera época de 10 bloques). La
  latencia PoW es hasta la PRIMERA inclusión en los 4 nodos (1 confirmación,
  reversible por un reorg); en PBFT la inclusión ya es final.
- "CPU" es el tiempo de CPU de todo el proceso (los 4 nodos juntos).
- La semilla fija el contenido de las TXs, el nodo de entrada y los tiempos de
  llegada; las llaves ECDSA y el minado no son deterministas.

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\experiments\\carrera_consensos.py
        [--tx 40] [--tasa 10] [--semilla 7] [--bits 14] [--salida docs/experimentos]
"""
import argparse
import contextlib
import csv
import json
import logging
import platform
import random
import socket
import statistics
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))

from blockchain.core.transaction import Transaction, TransactionType  # noqa: E402
from blockchain.core.wallet import Wallet  # noqa: E402

N_NODOS = 4


def _puertos_libres(n):
    socks = []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    puertos = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return puertos


def _esperar(cond, limite):
    fin = time.time() + limite
    while time.time() < fin:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _construir_apps(modo, directorio, bits):
    from api.app import create_app
    from config import build_settings
    ids = [f"node_{i + 1}" for i in range(N_NODOS)]
    puertos = _puertos_libres(N_NODOS)
    comunes = dict(node_host="127.0.0.1", node_advertise_host="127.0.0.1",
                   mining_difficulty=bits, log_level="WARNING", consensus=modo,
                   tx_rate_limit=10_000)
    if modo == "pbft":
        wallets = [Wallet.generate() for _ in ids]
        lista = directorio / "pbft_replicas.json"
        with open(lista, "w", encoding="utf-8") as f:
            json.dump({"replicas": [{"id": i, "address": f"127.0.0.1:{p}",
                                     "public_key": w.public_key_hex}
                                    for i, p, w in zip(ids, puertos, wallets)]}, f)
        for i, w in zip(ids, wallets):
            w.export(str(directorio / f"{i}_pbft.json"))
        comunes.update(pbft_replicas_file=str(lista), pbft_view_timeout=5.0,
                       pbft_batch_interval=0.05)
    apps = []
    for k, (nid, puerto) in enumerate(zip(ids, puertos)):
        extra = {"pbft_key_file": str(directorio / f"{nid}_pbft.json")} if modo == "pbft" else {}
        settings = build_settings(
            False, node_id=nid, node_port=puerto, data_dir=str(directorio / nid),
            authority_key_file=str(directorio / "sin_autoridad.json"),
            peers=[f"127.0.0.1:{p}" for p in puertos if p != puerto], **comunes, **extra)
        apps.append(create_app(settings))
    return apps


def _carga(n_tx, tasa, semilla):
    """TXs firmadas + (instante relativo, nodo de entrada) fijados por la semilla."""
    rng = random.Random(semilla)
    t, plan = 0.0, []
    for i in range(n_tx):
        w = Wallet.generate()
        tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address,
                         recipient="UPB_CARRERA",
                         payload={"i": i, "dato": "x" * rng.randint(16, 256)}, fee=0, nonce=1)
        tx.sign(w.private_key_hex)
        t += rng.expovariate(tasa)
        plan.append((t, rng.randrange(N_NODOS), tx))
    return plan


class _AbortarSiCambia:
    """``stop_event`` para el PoW: aborta si la cadena avanzó (llegó un bloque) o se termina."""

    def __init__(self, bc, fin):
        self.bc, self.h0, self.fin = bc, bc.height, fin

    def is_set(self):
        return self.fin.is_set() or self.bc.height != self.h0


def _minero(node, fin):
    """Mina mientras haya TXs pendientes (como /blocks/mine, sin HTTP)."""
    bc = node.blockchain
    while not fin.is_set():
        if not bc.mempool:
            time.sleep(0.01)
            continue
        cand = bc.create_candidate_block()
        res = node.pow_engine.mine(cand, timeout=60, difficulty=cand.header.difficulty,
                                   stop_event=_AbortarSiCambia(bc, fin))
        if res is None:
            continue
        ok, _ = bc.add_block(res.block)
        if ok:
            node.announce_block(res.block.to_dict())
            node.p2p.broadcast_block(res.block.to_dict())


def correr(modo, n_tx=40, tasa=10.0, semilla=7, bits=14, limite=180.0, convergencia=10.0,
           conexion=20.0):
    """Ejecuta un modo y devuelve ``(resumen, filas)``."""
    from fastapi.testclient import TestClient
    plan = _carga(n_tx, tasa, semilla)
    with tempfile.TemporaryDirectory(prefix=f"carrera-{modo}-",
                                     ignore_cleanup_errors=True) as tmp, \
            contextlib.ExitStack() as pila:
        apps = _construir_apps(modo, Path(tmp), bits)
        # Al salir: cerrar chain.db de cada nodo (Windows no borra archivos abiertos).
        pila.callback(lambda: [a.state.node.blockchain.close() for a in apps])
        for app in apps:
            pila.enter_context(TestClient(app))
        nodos = [a.state.node for a in apps]
        if not _esperar(lambda: all(n.p2p.get_network_stats()["active_peers"] >= N_NODOS - 1
                                    for n in nodos), conexion):
            raise RuntimeError("los nodos no se conectaron entre sí")
        fin = threading.Event()
        mineros = []
        if modo == "pow":
            for n in nodos:
                t = threading.Thread(target=_minero, args=(n, fin), daemon=True)
                t.start()
                mineros.append(t)
        msgs0 = sum(n.p2p.get_network_stats()["messages_sent"] for n in nodos)
        cpu0, t0 = time.process_time(), time.perf_counter()
        enviada, confirmada = {}, {}

        def vigilar():
            while not fin.is_set() and len(confirmada) < n_tx:
                ahora = time.perf_counter()
                for tx_id in list(enviada):
                    if tx_id not in confirmada and all(
                            n.blockchain.store.find_tx(tx_id) is not None for n in nodos):
                        confirmada[tx_id] = ahora
                time.sleep(0.005)
        vigia = threading.Thread(target=vigilar, daemon=True)
        vigia.start()
        for instante, k, tx in plan:
            espera = t0 + instante - time.perf_counter()
            if espera > 0:
                time.sleep(espera)
            n = nodos[k]
            ok, motivo = n.blockchain.add_transaction(tx)
            if not ok:
                raise RuntimeError(f"TX rechazada: {motivo}")
            enviada[tx.tx_id] = time.perf_counter()
            n.p2p.broadcast_transaction(tx.to_dict())
        _esperar(lambda: len(confirmada) == n_tx, limite)
        fin.set()
        vigia.join(timeout=2)
        for t in mineros:
            t.join(timeout=5)
        cpu = time.process_time() - cpu0
        msgs = sum(n.p2p.get_network_stats()["messages_sent"] for n in nodos) - msgs0

        def convergieron():
            # PoW: un bloque minado al final puede seguir propagándose; se fuerza la
            # sincronización (fuera de la medición) y se espera hasta `convergencia` s.
            for n in nodos:
                n.p2p.sync_with_peers()
            return len({n.blockchain.last_block.hash for n in nodos}) == 1
        _esperar(convergieron, convergencia)
        alturas = [n.blockchain.height for n in nodos]
        iguales = len({n.blockchain.last_block.hash for n in nodos}) == 1
        cambios_vista = max((n.pbft.view_changes_total for n in nodos if n.pbft), default=0)
        reorgs = sum(1 for n in nodos for a in n.security_monitor.get_alerts()
                     if a["event_type"] == "CHAIN_REORG")
    filas = []
    for instante, k, tx in plan:
        conf = confirmada.get(tx.tx_id)
        filas.append({"modo": modo, "tx": tx.tx_id[:16], "nodo_entrada": k + 1,
                      "t_envio_s": round(enviada[tx.tx_id] - t0, 4),
                      "latencia_ms": round((conf - enviada[tx.tx_id]) * 1000, 1) if conf else ""})
    lat = [f["latencia_ms"] for f in filas if f["latencia_ms"] != ""]
    ultimo = max(confirmada.values()) if confirmada else time.perf_counter()
    primero = min(enviada.values())
    resumen = {
        "modo": modo, "tx_enviadas": n_tx, "tx_confirmadas": len(lat),
        "latencia_media_ms": round(statistics.mean(lat), 1) if lat else None,
        "latencia_p50_ms": round(statistics.median(lat), 1) if lat else None,
        "latencia_p95_ms": round(sorted(lat)[max(0, int(0.95 * len(lat)) - 1)], 1) if lat else None,
        "latencia_max_ms": round(max(lat), 1) if lat else None,
        "tps": round(len(lat) / (ultimo - primero), 2) if lat and ultimo > primero else None,
        "bloques": max(alturas), "alturas_finales": "/".join(map(str, alturas)),
        "cadenas_iguales": iguales,
        "cpu_proceso_s": round(cpu, 2), "mensajes_p2p": msgs,
        "reorgs": reorgs, "cambios_de_vista": cambios_vista,
        "bits_pow": bits if modo == "pow" else 0,
    }
    return resumen, filas


def _escribir(salida, resumenes, filas, args):
    salida.mkdir(parents=True, exist_ok=True)
    with open(salida / "carrera_consensos.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    maquina = f"{platform.system()} {platform.release()}, {platform.machine()}, Python {platform.python_version()}"
    cols = ["modo", "tx_confirmadas", "latencia_media_ms", "latencia_p50_ms", "latencia_p95_ms",
            "latencia_max_ms", "tps", "bloques", "cpu_proceso_s", "mensajes_p2p", "reorgs",
            "cambios_de_vista", "alturas_finales", "cadenas_iguales"]
    lineas = [
        "# Carrera de consensos: PoW vs PBFT (P1-1)", "",
        "> **Medido en un portátil de desarrollo, red en proceso (loopback), 4 nodos en un "
        "mismo intérprete de Python. NO son mediciones en Raspberry Pi ni en LAN** (esas son P1-10).",
        "", f"- Fecha: {fecha}", f"- Máquina: {maquina}",
        f"- Carga: {args.tx} TX `DATA_RECORD`, llegadas de Poisson a {args.tasa} TX/s, "
        f"semilla {args.semilla}, nodo de entrada al azar (misma carga en ambos modos)",
        f"- PoW: 4 mineros, dificultad fija {args.bits} bits, minan solo con TXs pendientes. "
        "PBFT: 4 réplicas (f = 1), el primario propone cada ≥ 0,05 s si hay TXs.",
        "- Latencia = desde que la TX entra al mempool de un nodo hasta que está en la cadena de "
        "los 4 nodos. En PoW es la primera inclusión (1 confirmación, reversible); en PBFT es final.",
        "- `tps` = TX confirmadas / (última confirmación − primer envío) con ESTA carga ofrecida; "
        "no es la capacidad máxima (si un modo da cerca de la tasa ofrecida, está limitado por la carga).",
        "- `cpu_proceso_s` = CPU de todo el proceso (los 4 nodos juntos). `mensajes_p2p` = mensajes "
        "enviados por los 4 nodos durante la carga.",
        "- `cadenas_iguales` = misma punta en los 4 nodos al terminar (tras forzar una sincronización). "
        "En PoW puede ser False por un empate: dos puntas con el mismo trabajo, cada nodo conserva "
        "la suya hasta el próximo bloque (regla de Nakamoto); ver `alturas_finales`.",
        "- Regenerar: `venv\\Scripts\\python.exe scripts\\experiments\\carrera_consensos.py`",
        "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in resumenes:
        lineas.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    lineas += ["", "Detalle por TX en `carrera_consensos.csv`.", ""]
    with open(salida / "carrera_consensos.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lineas))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--tx", type=int, default=40)
    parser.add_argument("--tasa", type=float, default=10.0, help="TX por segundo (media)")
    parser.add_argument("--semilla", type=int, default=7)
    parser.add_argument("--bits", type=int, default=14, help="dificultad PoW en bits")
    parser.add_argument("--salida", default=str(RAIZ / "docs" / "experimentos"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    for nombre in ("upb_chain", "upb_chain.network", "upb_chain.pbft"):
        logging.getLogger(nombre).setLevel(logging.ERROR)
    resumenes, filas = [], []
    for modo in ("pow", "pbft"):
        print(f"Corriendo {modo}...", flush=True)
        r, f = correr(modo, args.tx, args.tasa, args.semilla, args.bits)
        print(json.dumps(r, ensure_ascii=False), flush=True)
        resumenes.append(r)
        filas.extend(f)
    _escribir(Path(args.salida), resumenes, filas, args)
    print(f"Escrito en {args.salida}")


if __name__ == "__main__":
    main()
