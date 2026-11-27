"""Benchmark de hardware para UPB-Chain (P1-10): pensado para la Raspberry Pi 5.

Mide, con el MISMO código que usa el nodo:
  1. Hash rate: hashes/s de ``Block.compute_hash`` (SHA-256 sobre el JSON del bloque).
  2. Curva dificultad/tiempo: minado real (``ProofOfWork.mine``) de varios bloques por
     cada dificultad en bits; tiempo medio, intentos medios y el esperado (2**bits).
  3. Temperatura de la CPU (``vcgencmd measure_temp``, o ``/sys/class/thermal``), antes
     y después de la carga; "no disponible" si el equipo no la expone.
  4. RAM: total/disponible del sistema y pico de memoria del propio proceso.
  5. TPS: construir+firmar, admitir al mempool (validación de firma y contratos) y
     minar+validar+aplicar bloques de 50 TXs, en proceso, con un DATA_DIR temporal.
  6. TPS con PBFT: 4 réplicas en proceso (f=1, red en memoria), bloques de hasta 50 TXs
     con certificado de commit; fases firma/admisión/consenso y latencia de commit por
     bloque (mediana/p95). Se elige con ``--consenso pow|pbft|ambos`` (por defecto ambos).

Escribe un informe Markdown y un CSV; cada número lleva el equipo donde se midió
(plataforma, CPU, Python, fecha). No toca ``data/`` ni abre puertos. Los números
de una ejecución en un portátil NO son los de la Raspberry Pi: el dueño de las RPi
debe ejecutarlo en cada Pi (ver ``docs/benchmark_hardware.md``).

Uso (desde la raíz del repo)::

    venv/bin/python scripts/bench_rpi.py                  # medición completa
    venv/bin/python scripts/bench_rpi.py --consenso pbft  # pow | pbft | ambos
    venv/bin/python scripts/bench_rpi.py --rapido         # corrida corta (CI/pruebas)
    venv/bin/python scripts/bench_rpi.py --salida /ruta   # directorio de resultados
"""
import argparse
import csv
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from blockchain.consensus.proof_of_work import ProofOfWork  # noqa: E402
from blockchain.core.block import Block, BlockHeader  # noqa: E402
from blockchain.core.chain import Blockchain  # noqa: E402
from blockchain.core.transaction import (  # noqa: E402
    create_mint_transaction, create_transfer_transaction,
)
from blockchain.core.wallet import Wallet  # noqa: E402

NO_DISPONIBLE = "no disponible"

# Parámetros por modo: segundos de hash rate, bits de la curva, bloques por punto, TXs.
PERFILES = {
    "completo": dict(seg_hash=3.0, bits=[8, 12, 14, 16, 18], repeticiones=5, txs=500,
                     remitentes=10, txs_pbft=500),
    "rapido": dict(seg_hash=0.3, bits=[4, 8, 10], repeticiones=3, txs=60, remitentes=4, txs_pbft=60),
}


# ── Anfitrión, temperatura, RAM ──────────────────────────────────────────────

def _modelo_cpu() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for linea in f:
                clave = linea.split(":", 1)[0].strip().lower()
                if clave in ("model name", "model", "hardware") and ":" in linea:
                    return linea.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or NO_DISPONIBLE


def info_host() -> dict:
    """Dónde se mide: toda cifra del informe se etiqueta con esto."""
    return {
        "anfitrion": socket.gethostname(),
        "plataforma": platform.platform(),
        "arquitectura": platform.machine(),
        "cpu": _modelo_cpu(),
        "nucleos": os.cpu_count() or 0,
        # Carga de los últimos 60 s al empezar: si es alta (nodos corriendo en la misma Pi) el
        # benchmark mide una máquina ocupada. No existe en Windows.
        "carga_1min": round(os.getloadavg()[0], 2) if hasattr(os, "getloadavg") else NO_DISPONIBLE,
        "python": platform.python_version(),
        "fecha_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }


def leer_temperatura():
    """Temperatura de la CPU en °C o None. Orden: vcgencmd, luego sysfs."""
    try:
        r = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True,
                           timeout=3, check=False)
        if r.returncode == 0 and "temp=" in r.stdout:
            return float(r.stdout.split("temp=")[1].split("'")[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", encoding="utf-8") as f:
            return int(f.read().strip()) / 1000.0
    except (OSError, ValueError):
        return None


def _kb_de(ruta: str, claves: tuple) -> dict:
    out = {}
    try:
        with open(ruta, encoding="utf-8") as f:
            for linea in f:
                k, _, v = linea.partition(":")
                if k in claves:
                    out[k] = int(v.split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return out


def _ram_windows() -> tuple:
    """(sistema, proceso) en KiB con ctypes (solo para desarrollo en Windows)."""
    import ctypes
    from ctypes import wintypes

    class MemEstado(ctypes.Structure):
        _fields_ = [("largo", wintypes.DWORD), ("carga", wintypes.DWORD),
                    ("total", ctypes.c_uint64), ("libre", ctypes.c_uint64),
                    ("pag_total", ctypes.c_uint64), ("pag_libre", ctypes.c_uint64),
                    ("virt_total", ctypes.c_uint64), ("virt_libre", ctypes.c_uint64),
                    ("ext", ctypes.c_uint64)]

    class MemProceso(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("fallos", wintypes.DWORD),
                    ("pico", ctypes.c_size_t), ("ws", ctypes.c_size_t),
                    ("a", ctypes.c_size_t), ("b", ctypes.c_size_t), ("c", ctypes.c_size_t),
                    ("d", ctypes.c_size_t), ("e", ctypes.c_size_t), ("f", ctypes.c_size_t)]
    try:
        sis = MemEstado()
        sis.largo = ctypes.sizeof(MemEstado)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(sis))
        proc = MemProceso()
        proc.cb = ctypes.sizeof(MemProceso)
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(MemProceso), wintypes.DWORD]
        ctypes.windll.psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(),
                                                 ctypes.byref(proc), proc.cb)
        return ({"MemTotal": sis.total // 1024, "MemAvailable": sis.libre // 1024},
                {"VmRSS": proc.ws // 1024, "VmHWM": proc.pico // 1024})
    except (OSError, AttributeError):
        return {}, {}


def leer_ram() -> dict:
    """RAM en MiB (solo biblioteca estándar): total/disponible del sistema y
    memoria residente (actual y pico) del proceso. ``None`` si no se puede leer."""
    mem = _kb_de("/proc/meminfo", ("MemTotal", "MemAvailable"))
    yo = _kb_de("/proc/self/status", ("VmRSS", "VmHWM"))
    if not mem and sys.platform == "win32":
        mem, yo = _ram_windows()
    mib = lambda d, k: round(d[k] / 1024, 1) if k in d else None  # noqa: E731
    return {"total_mib": mib(mem, "MemTotal"), "disponible_mib": mib(mem, "MemAvailable"),
            "proceso_mib": mib(yo, "VmRSS"), "proceso_pico_mib": mib(yo, "VmHWM")}


# ── Mediciones ───────────────────────────────────────────────────────────────

def _bloque_de_prueba(indice: int) -> Block:
    cab = BlockHeader(index=indice, timestamp=1_700_000_000.0 + indice,
                      previous_hash="0" * 64, merkle_root="0" * 64, node_id="bench")
    return Block(header=cab, transactions=[])


def medir_hash_rate(segundos: float) -> dict:
    """Hashes/s de ``Block.compute_hash`` (bloque sin TXs), midiendo por lotes."""
    bloque = _bloque_de_prueba(1)
    n = 0
    inicio = time.perf_counter()
    while time.perf_counter() - inicio < segundos:
        for i in range(2000):
            bloque.header.nonce = n + i
            bloque.compute_hash()
        n += 2000
    t = time.perf_counter() - inicio
    return {"hashes": n, "segundos": round(t, 3), "hashes_por_s": round(n / t)}


def medir_curva(bits_lista, repeticiones: int) -> list:
    """Minado real por dificultad: tiempo e intentos medios sobre ``repeticiones`` bloques."""
    filas = []
    for bits in bits_lista:
        tiempos, intentos = [], []
        for r in range(repeticiones):
            res = ProofOfWork(difficulty=bits).mine(
                _bloque_de_prueba(1000 * bits + r), timeout=600.0)
            if res is None:
                continue
            tiempos.append(res.time_elapsed)
            intentos.append(res.attempts)
        filas.append({
            "bits": bits, "bloques": len(tiempos),
            "tiempo_medio_s": round(statistics.mean(tiempos), 4) if tiempos else None,
            "tiempo_max_s": round(max(tiempos), 4) if tiempos else None,
            "intentos_medios": round(statistics.mean(intentos)) if intentos else None,
            "intentos_esperados": 1 << bits,
        })
    return filas


def medir_tps(n_txs: int, remitentes: int, bits: int = 4) -> dict:
    """TPS en proceso: firmar, admitir al mempool y minar+validar+aplicar bloques.

    Usa un directorio temporal y una autoridad local de usar y tirar. Las TXs son
    TOKEN_TRANSFER entre ``remitentes`` cuentas con saldo previo (TOKEN_MINT)."""
    tmp = tempfile.mkdtemp(prefix="upb_bench_")
    bc = None
    try:
        autoridad = Wallet.generate()
        bc = Blockchain("bench", tmp, initial_difficulty=bits, min_difficulty=bits,
                        max_difficulty=bits + 4, authority_address=autoridad.address)
        cuentas = [Wallet.generate() for _ in range(remitentes)]
        destino = Wallet.generate().address

        def vaciar_mempool() -> int:
            bloques = 0
            while bc.mempool:
                cand = bc.create_candidate_block()
                res = ProofOfWork(difficulty=cand.header.difficulty).mine(
                    cand, timeout=600.0, difficulty=cand.header.difficulty)
                ok, motivo = bc.add_block(res.block)
                if not ok:
                    raise RuntimeError(f"bloque rechazado en el benchmark: {motivo}")
                bloques += 1
            return bloques

        for c in cuentas:   # saldo inicial (no se cuenta en el TPS)
            tx = create_mint_transaction(autoridad.address, c.address, 10 ** 9,
                                         autoridad.private_key_hex,
                                         bc.next_nonce(autoridad.address))
            ok, motivo = bc.add_transaction(tx)
            if not ok:
                raise RuntimeError(motivo)
        vaciar_mempool()

        nonces = {c.address: bc.next_nonce(c.address) for c in cuentas}
        t0 = time.perf_counter()
        txs = []
        for i in range(n_txs):
            c = cuentas[i % remitentes]
            txs.append(create_transfer_transaction(c.address, destino, 1, c.private_key_hex,
                                                   nonces[c.address]))
            nonces[c.address] += 1
        t_firma = time.perf_counter() - t0

        t0 = time.perf_counter()
        for tx in txs:
            ok, motivo = bc.add_transaction(tx)
            if not ok:
                raise RuntimeError(f"TX rechazada en el benchmark: {motivo}")
        t_admision = time.perf_counter() - t0

        t0 = time.perf_counter()
        bloques = vaciar_mempool()
        t_bloques = time.perf_counter() - t0

        total = t_firma + t_admision + t_bloques
        return {
            "txs": n_txs, "bloques": bloques, "bits_minado": bits,
            "firma_s": round(t_firma, 3), "admision_s": round(t_admision, 3),
            "bloques_s": round(t_bloques, 3),
            "tps_firma": round(n_txs / t_firma, 1) if t_firma else None,
            "tps_admision": round(n_txs / t_admision, 1) if t_admision else None,
            "tps_bloques": round(n_txs / t_bloques, 1) if t_bloques else None,
            "tps_total": round(n_txs / total, 1) if total else None,
        }
    finally:
        if bc is not None:
            bc.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _percentil(valores: list, q: float):
    """Percentil por rango más cercano (sin interpolar); None si no hay datos."""
    if not valores:
        return None
    ordenados = sorted(valores)
    return ordenados[min(len(ordenados) - 1, max(0, round(q * len(ordenados) + 0.5) - 1))]


def medir_tps_pbft(n_txs: int, remitentes: int, replicas: int = 4) -> dict:
    """TPS con PBFT: ``replicas`` réplicas (f=1 con 4) en proceso y red en memoria.

    La entrega es síncrona (``InMemoryNetwork``): no hay red ni hilos, así que se mide
    el coste de CPU del protocolo (firmas ECDSA de los mensajes, certificado de commit,
    validación y SQLite en cada réplica), no la latencia de una red. Usa directorios
    temporales y una autoridad local de usar y tirar."""
    from blockchain.consensus.pbft import InMemoryNetwork, PBFTReplica, ReplicaSet

    tmp = tempfile.mkdtemp(prefix="upb_bench_pbft_")
    cadenas = []
    try:
        autoridad = Wallet.generate()
        wallets = [Wallet.generate() for _ in range(replicas)]
        ids = [f"r{i}" for i in range(replicas)]
        rs = ReplicaSet.from_list([
            {"id": rid, "address": f"127.0.0.1:{9000 + i}", "public_key": w.public_key_hex}
            for i, (rid, w) in enumerate(zip(ids, wallets))])
        red = InMemoryNetwork()
        reps = []
        for rid, w in zip(ids, wallets):
            bc = Blockchain(rid, os.path.join(tmp, rid), consensus="pbft", replica_set=rs,
                            authority_address=autoridad.address)
            cadenas.append(bc)
            r = PBFTReplica(rid, w.private_key_hex, rs, bc, red.sender(rid),
                            view_timeout=60.0, batch_interval=0.0)
            red.add(r)
            reps.append(r)

        def difundir(tx) -> None:
            """Gossip simulado: la TX entra al mempool de todas las réplicas."""
            for bc in cadenas:
                ok, motivo = bc.add_transaction(tx)
                if not ok:
                    raise RuntimeError(f"TX rechazada en el benchmark PBFT: {motivo}")

        def confirmar() -> list:
            """Tick hasta vaciar el mempool; devuelve la latencia de commit de cada bloque
            (desde que el primario propone hasta que las réplicas lo tienen en su cadena)."""
            lat = []
            while cadenas[0].mempool:
                h0 = cadenas[0].height
                t0 = time.perf_counter()
                for _ in range(20):
                    for r in reps:
                        r.tick()
                    if all(bc.height > h0 for bc in cadenas):
                        break
                else:
                    raise RuntimeError("PBFT no confirmó el bloque en el benchmark")
                lat.append(time.perf_counter() - t0)
            return lat

        cuentas = [Wallet.generate() for _ in range(remitentes)]
        destino = Wallet.generate().address
        for c in cuentas:   # saldo inicial (no se cuenta)
            difundir(create_mint_transaction(autoridad.address, c.address, 10 ** 9,
                                             autoridad.private_key_hex,
                                             cadenas[0].next_nonce(autoridad.address)))
        confirmar()

        nonces = {c.address: cadenas[0].next_nonce(c.address) for c in cuentas}
        t0 = time.perf_counter()
        txs = []
        for i in range(n_txs):
            c = cuentas[i % remitentes]
            txs.append(create_transfer_transaction(c.address, destino, 1, c.private_key_hex,
                                                   nonces[c.address]))
            nonces[c.address] += 1
        t_firma = time.perf_counter() - t0

        t0 = time.perf_counter()
        for tx in txs:
            difundir(tx)
        t_admision = time.perf_counter() - t0

        t0 = time.perf_counter()
        lat = confirmar()
        t_consenso = time.perf_counter() - t0
        alturas = {bc.height for bc in cadenas}
        if len(alturas) != 1:
            raise RuntimeError(f"las réplicas divergieron: {alturas}")

        total = t_firma + t_admision + t_consenso
        ms = lambda x: None if x is None else round(x * 1000, 1)  # noqa: E731
        return {
            "txs": n_txs, "replicas": replicas, "f": rs.f, "bloques": len(lat),
            "firma_s": round(t_firma, 3), "admision_s": round(t_admision, 3),
            "consenso_s": round(t_consenso, 3),
            "tps_firma": round(n_txs / t_firma, 1) if t_firma else None,
            "tps_admision": round(n_txs / t_admision, 1) if t_admision else None,
            "tps_consenso": round(n_txs / t_consenso, 1) if t_consenso else None,
            "tps": round(n_txs / total, 1) if total else None,
            "latencia_commit_mediana_ms": ms(statistics.median(lat)) if lat else None,
            "latencia_commit_p95_ms": ms(_percentil(lat, 0.95)),
        }
    finally:
        for bc in cadenas:
            bc.close()
        shutil.rmtree(tmp, ignore_errors=True)


def ejecutar(perfil: str = "completo", consenso: str = "ambos") -> dict:
    """Corre las mediciones del perfil y devuelve los resultados.

    ``consenso``: "pow" (hash rate, curva y TPS de un nodo), "pbft" (solo el TPS con
    PBFT) o "ambos"."""
    if consenso not in ("pow", "pbft", "ambos"):
        raise ValueError("consenso debe ser pow, pbft o ambos")
    p = PERFILES[perfil]
    r = {"perfil": perfil, "consenso": consenso, "host": info_host()}
    temp_ini = leer_temperatura()
    if consenso in ("pow", "ambos"):
        r["hash_rate"] = medir_hash_rate(p["seg_hash"])
        r["curva"] = medir_curva(p["bits"], p["repeticiones"])
        r["tps"] = medir_tps(p["txs"], p["remitentes"])
    if consenso in ("pbft", "ambos"):
        r["tps_pbft"] = medir_tps_pbft(p["txs_pbft"], p["remitentes"])
    r.update(temperatura_inicial_c=temp_ini, temperatura_final_c=leer_temperatura(),
             ram=leer_ram())
    return r


# ── Modo --termico (idea 5): freno térmico del minero, apagado vs encendido ──────

def _minar_n_segundos(segundos: float, bits: int, freno, muestreo_s: float, fuente) -> dict:
    """Mina bloques de prueba seguidos durante ``segundos`` y muestrea temperatura y hash rate."""
    pow_ = ProofOfWork(difficulty=bits, freno=freno)
    t0 = time.perf_counter()
    muestras, hashes_hechos, semilla = [], 0, 0
    estado = {"ult_t": t0, "ult_h": 0, "base": 0}

    def tomar(nonce_actual: int) -> None:
        estado["nonce"] = nonce_actual
        ahora = time.perf_counter()
        if ahora - estado["ult_t"] < muestreo_s:
            return
        total = estado["base"] + nonce_actual
        muestras.append({
            "t_s": round(ahora - t0, 2), "temperatura_c": fuente(),
            "ciclo": round(freno.ciclo, 3) if freno is not None else 1.0,
            "hash_rate": round((total - estado["ult_h"]) / (ahora - estado["ult_t"]))})
        estado["ult_t"], estado["ult_h"] = ahora, total

    bloques = 0
    while True:
        resto = segundos - (time.perf_counter() - t0)
        if resto <= 0:
            break
        res = pow_.mine(_bloque_de_prueba(5_000_000 + semilla), timeout=resto,
                        on_progress=lambda n, _s: tomar(n))
        semilla += 1
        if res is None:   # se acabó el tiempo a mitad de un bloque
            break
        bloques += 1
        hashes_hechos += res.attempts
        estado["base"] = hashes_hechos
        estado["nonce"] = 0
    tomar_final = time.perf_counter() - t0
    return {"segundos": round(tomar_final, 2), "bloques": bloques, "bits": bits,
            "hashes": hashes_hechos + estado.get("nonce", 0),
            "hash_rate_medio": round((hashes_hechos + estado.get("nonce", 0)) / tomar_final) if tomar_final > 0 else 0,
            "muestras": muestras}


def medir_termico(segundos: float, bits: int, soft_c: float = 70.0, hard_c: float = 80.0,
                  min_duty: float = 0.2, muestreo_s: float = 5.0, fuente=None) -> dict:
    """Mina ``segundos`` con el freno térmico apagado y luego encendido, y devuelve la curva
    de temperatura y el hash rate de cada tramo. Es una HIPÓTESIS a medir: no hay cifras
    precargadas. ``fuente`` (opcional) sustituye al sensor, para pruebas."""
    from blockchain.consensus.termico import FrenoTermico
    fuente = fuente or leer_temperatura
    out = {"segundos_por_tramo": segundos, "soft_c": soft_c, "hard_c": hard_c,
           "min_duty": min_duty, "temperatura_inicial_c": fuente()}
    out["sin_freno"] = _minar_n_segundos(segundos, bits, None, muestreo_s, fuente)
    out["con_freno"] = _minar_n_segundos(
        segundos, bits, FrenoTermico(soft_c, hard_c, min_duty, fuente=fuente),
        muestreo_s, fuente)
    out["temperatura_final_c"] = fuente()
    return out


def guardar_termico(t: dict, salida: Path) -> tuple:
    salida.mkdir(parents=True, exist_ok=True)
    sello = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"bench_termico_{info_host()['anfitrion']}_{sello}"
    md, cs = salida / f"{base}.md", salida / f"{base}.csv"
    L = ["# Freno térmico del minero: apagado vs encendido (hipótesis a medir)", "",
         f"Tramo de {t['segundos_por_tramo']} s cada uno; umbrales {t['soft_c']}/{t['hard_c']} °C, "
         f"ciclo mínimo {t['min_duty']}. Temperatura inicial: {_t(t['temperatura_inicial_c'], ' °C')}; "
         f"final: {_t(t['temperatura_final_c'], ' °C')}.", "",
         "| Tramo | Bloques | Hash rate medio (H/s) |", "|---|---|---|"]
    filas = [("config", k, t[k]) for k in ("segundos_por_tramo", "soft_c", "hard_c", "min_duty")]
    for nombre in ("sin_freno", "con_freno"):
        x = t[nombre]
        L.append(f"| {nombre} | {x['bloques']} | {x['hash_rate_medio']} |")
        filas.append((nombre, "hash_rate_medio", x["hash_rate_medio"]))
        for m in x["muestras"]:
            filas.append((nombre, f"t={m['t_s']}s",
                          f"temp_c={_t(m['temperatura_c'])};ciclo={m['ciclo']};hash_rate={m['hash_rate']}"))
    L += ["", "Curva de temperatura: ver el CSV (una fila por muestra).", ""]
    md.write_text("\n".join(L), encoding="utf-8")
    with open(cs, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seccion", "clave", "valor"])
        w.writerows(filas)
    return md, cs


# ── Informe ──────────────────────────────────────────────────────────────────

def _t(valor, unidad="") -> str:
    return NO_DISPONIBLE if valor is None else f"{valor}{unidad}"


def informe_markdown(r: dict) -> str:
    h, ram = r["host"], r["ram"]
    L = [f"# Resultados de benchmark UPB-Chain ({r['perfil']})", "",
         "Medido en el equipo descrito abajo; los números NO se extrapolan a otro hardware.", "",
         "## Equipo", "",
         "| Campo | Valor |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in h.items()]
    if "tps" in r:
        L += _md_pow(r)
    if "tps_pbft" in r:
        L += _md_pbft(r["tps_pbft"])
    L += ["", "## Temperatura", "",
          f"- Antes de la carga: {_t(r['temperatura_inicial_c'], ' °C')}",
          f"- Después de la carga: {_t(r['temperatura_final_c'], ' °C')}", "",
          "## RAM", "",
          f"- Total del sistema: {_t(ram['total_mib'], ' MiB')}",
          f"- Disponible: {_t(ram['disponible_mib'], ' MiB')}",
          f"- Proceso (actual / pico): {_t(ram['proceso_mib'], ' MiB')} / "
          f"{_t(ram['proceso_pico_mib'], ' MiB')}", ""]
    return "\n".join(L)


def _md_pow(r: dict) -> list:
    hr, tps = r["hash_rate"], r["tps"]
    L = []
    L += ["", "## Hash rate", "",
          "| Hashes | Segundos | Hashes/s |", "|---:|---:|---:|",
          f"| {hr['hashes']} | {hr['segundos']} | {hr['hashes_por_s']} |", "",
          "## Curva dificultad/tiempo", "",
          "| Bits | Bloques | Tiempo medio (s) | Tiempo máx. (s) | Intentos medios | "
          "Intentos esperados (2^bits) |", "|---:|---:|---:|---:|---:|---:|"]
    L += [f"| {c['bits']} | {c['bloques']} | {_t(c['tiempo_medio_s'])} | "
          f"{_t(c['tiempo_max_s'])} | {_t(c['intentos_medios'])} | {c['intentos_esperados']} |"
          for c in r["curva"]]
    L += ["", "## TPS (en proceso, un solo nodo)", "",
          "| Fase | Segundos | TX/s |", "|---|---:|---:|",
          f"| Construir y firmar | {tps['firma_s']} | {_t(tps['tps_firma'])} |",
          f"| Admitir al mempool (validación) | {tps['admision_s']} | {_t(tps['tps_admision'])} |",
          f"| Minar, validar y aplicar bloques | {tps['bloques_s']} | {_t(tps['tps_bloques'])} |",
          f"| Total | {round(tps['firma_s'] + tps['admision_s'] + tps['bloques_s'], 3)} | "
          f"{_t(tps['tps_total'])} |", "",
          f"{tps['txs']} TX TOKEN_TRANSFER en {tps['bloques']} bloques, minado a "
          f"{tps['bits_minado']} bits (el minado casi no pesa: el TPS refleja firma, "
          "validación y SQLite).", ""]
    return L


def _md_pbft(t: dict) -> list:
    return ["", "## TPS con PBFT (en proceso, réplicas en memoria)", "",
            "| Fase | Segundos | TX/s |", "|---|---:|---:|",
            f"| Construir y firmar | {t['firma_s']} | {_t(t['tps_firma'])} |",
            f"| Admitir al mempool de las {t['replicas']} réplicas | {t['admision_s']} | "
            f"{_t(t['tps_admision'])} |",
            f"| Consenso PBFT (commit con certificado) | {t['consenso_s']} | "
            f"{_t(t['tps_consenso'])} |",
            f"| Total | {round(t['firma_s'] + t['admision_s'] + t['consenso_s'], 3)} | "
            f"{_t(t['tps'])} |", "",
            f"{t['txs']} TX TOKEN_TRANSFER en {t['bloques']} bloques (hasta 50 TX), "
            f"{t['replicas']} réplicas (f={t['f']}). Latencia de commit por bloque "
            f"(hasta que las {t['replicas']} réplicas lo tienen): mediana "
            f"{_t(t['latencia_commit_mediana_ms'], ' ms')}, p95 "
            f"{_t(t['latencia_commit_p95_ms'], ' ms')}. Red en memoria y un solo "
            "intérprete: mide CPU del protocolo, no red.", ""]



def escribir_csv(r: dict, ruta: Path) -> None:
    """CSV en formato largo (``seccion,clave,valor``), fácil de pegar en una hoja."""
    filas = [("equipo", k, v) for k, v in r["host"].items()]
    if "tps" in r:
        filas += [("hash_rate", k, v) for k, v in r["hash_rate"].items()]
        for c in r["curva"]:
            filas += [(f"curva_{c['bits']}bits", k, v) for k, v in c.items()]
        filas += [("tps", k, v) for k, v in r["tps"].items()]
    if "tps_pbft" in r:
        filas += [("tps_pbft", k, v) for k, v in r["tps_pbft"].items()]
    filas += [("temperatura", "inicial_c", _t(r["temperatura_inicial_c"])),
              ("temperatura", "final_c", _t(r["temperatura_final_c"]))]
    filas += [("ram", k, _t(v)) for k, v in r["ram"].items()]
    with open(ruta, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seccion", "clave", "valor"])
        w.writerows(filas)


def guardar(r: dict, salida: Path) -> tuple:
    salida.mkdir(parents=True, exist_ok=True)
    sello = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"bench_{r['host']['anfitrion']}_{r['perfil']}_{sello}"
    md, cs = salida / f"{base}.md", salida / f"{base}.csv"
    md.write_text(informe_markdown(r), encoding="utf-8")
    escribir_csv(r, cs)
    return md, cs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rapido", action="store_true", help="corrida corta (CI/pruebas)")
    ap.add_argument("--salida", default=str(RAIZ / "docs" / "mediciones"),
                    help="directorio de resultados (.md y .csv)")
    ap.add_argument("--consenso", choices=("pow", "pbft", "ambos"), default="ambos",
                    help="qué medir: pow (un nodo), pbft (4 réplicas) o ambos (por defecto)")
    ap.add_argument("--termico", action="store_true",
                    help="solo mide el freno térmico del minero (apagado vs encendido)")
    ap.add_argument("--termico-segundos", type=float, default=None,
                    help="segundos por tramo (por defecto 300; con --rapido, 2)")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.termico:
        seg = args.termico_segundos or (2.0 if args.rapido else 300.0)
        t = medir_termico(seg, bits=8 if args.rapido else 24,
                          muestreo_s=0.5 if args.rapido else 5.0)
        md, cs = guardar_termico(t, Path(args.salida))
        print(md.read_text(encoding="utf-8"))
        print(f"Escrito: {md}\nEscrito: {cs}")
        return
    r = ejecutar("rapido" if args.rapido else "completo", args.consenso)
    md, cs = guardar(r, Path(args.salida))
    print(informe_markdown(r))
    print(f"Escrito: {md}\nEscrito: {cs}")


if __name__ == "__main__":
    main()
