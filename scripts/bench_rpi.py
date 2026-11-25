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

Escribe un informe Markdown y un CSV; cada número lleva el equipo donde se midió
(plataforma, CPU, Python, fecha). No toca ``data/`` ni abre puertos. Los números
de una ejecución en un portátil NO son los de la Raspberry Pi: el dueño de las RPi
debe ejecutarlo en cada Pi (ver ``docs/benchmark_hardware.md``).

Uso (desde la raíz del repo)::

    venv/bin/python scripts/bench_rpi.py                  # medición completa
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
                     remitentes=10),
    "rapido": dict(seg_hash=0.3, bits=[4, 8, 10], repeticiones=3, txs=60, remitentes=4),
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


def ejecutar(perfil: str = "completo") -> dict:
    """Corre todas las mediciones del perfil y devuelve los resultados."""
    p = PERFILES[perfil]
    host = info_host()
    temp_ini = leer_temperatura()
    hash_rate = medir_hash_rate(p["seg_hash"])
    curva = medir_curva(p["bits"], p["repeticiones"])
    tps = medir_tps(p["txs"], p["remitentes"])
    return {
        "perfil": perfil, "host": host, "hash_rate": hash_rate, "curva": curva, "tps": tps,
        "temperatura_inicial_c": temp_ini, "temperatura_final_c": leer_temperatura(),
        "ram": leer_ram(),
    }


# ── Informe ──────────────────────────────────────────────────────────────────

def _t(valor, unidad="") -> str:
    return NO_DISPONIBLE if valor is None else f"{valor}{unidad}"


def informe_markdown(r: dict) -> str:
    h, hr, tps, ram = r["host"], r["hash_rate"], r["tps"], r["ram"]
    L = [f"# Resultados de benchmark UPB-Chain ({r['perfil']})", "",
         "Medido en el equipo descrito abajo; los números NO se extrapolan a otro hardware.", "",
         "## Equipo", "",
         "| Campo | Valor |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in h.items()]
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
          "validación y SQLite).", "",
          "## Temperatura", "",
          f"- Antes de la carga: {_t(r['temperatura_inicial_c'], ' °C')}",
          f"- Después de la carga: {_t(r['temperatura_final_c'], ' °C')}", "",
          "## RAM", "",
          f"- Total del sistema: {_t(ram['total_mib'], ' MiB')}",
          f"- Disponible: {_t(ram['disponible_mib'], ' MiB')}",
          f"- Proceso (actual / pico): {_t(ram['proceso_mib'], ' MiB')} / "
          f"{_t(ram['proceso_pico_mib'], ' MiB')}", ""]
    return "\n".join(L)


def escribir_csv(r: dict, ruta: Path) -> None:
    """CSV en formato largo (``seccion,clave,valor``), fácil de pegar en una hoja."""
    filas = [("equipo", k, v) for k, v in r["host"].items()]
    filas += [("hash_rate", k, v) for k, v in r["hash_rate"].items()]
    for c in r["curva"]:
        filas += [(f"curva_{c['bits']}bits", k, v) for k, v in c.items()]
    filas += [("tps", k, v) for k, v in r["tps"].items()]
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
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    r = ejecutar("rapido" if args.rapido else "completo")
    md, cs = guardar(r, Path(args.salida))
    print(informe_markdown(r))
    print(f"Escrito: {md}\nEscrito: {cs}")


if __name__ == "__main__":
    main()
